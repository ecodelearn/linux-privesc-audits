# Auditoria: UFW, opensnitch e net_guard (2026-07-17)

Checklist de verificação real (testado, não só lido) do stack de firewall/controle de saída da `onlyletther`, mais um incidente encontrado e corrigido durante a própria correção. Complementa [`docs/systemd-attack-surface-reduction.md`](../../docs/systemd-attack-surface-reduction.md), mas foca em controle de rede/aplicação em vez de daemons systemd.

## Achado 1 (crítico): opensnitch rodando sem enforcement de verdade

Config em `/etc/opensnitchd/default-config.json` tinha:

```json
"DefaultAction": "allow",
"InterceptUnknown": false,
```

Com `/etc/opensnitchd/rules/` **vazio** (zero regras salvas). Resultado: o daemon estava ativo, monitorando via eBPF (`ProcMonitorMethod: ebpf`), logando tudo — mas **nunca bloqueava nem perguntava nada**. Qualquer processo novo conectava livremente. Isso derrota o propósito central de um firewall de aplicação (allow-list explícita, negar por padrão o que não foi decidido).

**Correção**: `DefaultAction: "deny"`, `InterceptUnknown: true`, restart do `opensnitchd`. Testado ao vivo: conexões novas sem regra passaram a cair em `deny` de fato (confirmado pelo usuário e pelo log, `journalctl -u opensnitchd`).

**Efeito colateral esperado, não bug**: com zero regras pré-existentes, os primeiros minutos/uso normal geram bastante popup de decisão — cada app que nunca teve uma conexão decidida antes vai perguntar uma vez. Regras com `duration: once` (o padrão) não persistem — se ninguém responder o popup a tempo, a conexão cai no `DefaultAction` (deny) mas nada fica gravado permanentemente; a próxima tentativa gera novo prompt.

### Sub-achado: ferramentas de automação (CLI) precisam de regra permanente

Sem regra salva, chamadas de `gh`/`git` feitas por automação (ex.: um agente rodando comandos sem alguém pra clicar no popup) caem em `deny` a cada nova conexão. Resolvido com duas regras `duration: always`:

```json
{
  "action": "allow",
  "duration": "always",
  "operator": { "type": "simple", "operand": "process.path", "data": "/usr/bin/gh", "sensitive": false }
}
```
(mesmo padrão pra `/usr/bin/git`, arquivos em `/etc/opensnitchd/rules/allow-simple-usr-bin-{gh,git}.json`)

Formato de regra confirmado contra a [wiki oficial de Rules](https://github.com/evilsocket/opensnitch/wiki/Rules) antes de aplicar.

## Achado 2: `network_aliases.json` faltando

`/etc/opensnitchd/network_aliases.json` não existia (warning no log: `open /etc/opensnitchd/network_aliases.json: no such file or directory`). Esse arquivo dá nome legível a faixas de IP nos prompts/logs do opensnitch, em vez de só mostrar o IP cru. Formato confirmado contra o arquivo padrão real do projeto ([`daemon/data/network_aliases.json`](https://github.com/evilsocket/opensnitch/blob/master/daemon/data/network_aliases.json)):

```json
{ "AliasName": ["cidr1", "cidr2", ...] }
```

Recriado com os defaults do próprio projeto (LAN, MULTICAST) mais os servidores próprios do usuário (Contabo1/Contabo2 — ver [[project_contabo_servers]] equivalente neste repo, os IPs aparecem com frequência agora que `deny` está ativo).

## Achado 3: UFW — nada a corrigir, mas vale registrar como baseline confirmado

Todas as 21 regras de "porta de atacante conhecida" documentadas anteriormente (NTP, SMTP, NetBIOS, SMB, NetBus, SubSeven, BackOrifice, MSSQL, RDP, VNC, IRC, Metasploit) confirmadas presentes em IPv4 e IPv6, política padrão `deny incoming / allow outgoing`, sem nenhuma regra `ALLOW IN` inesperada. Log do kernel (`journalctl -k --grep "UFW BLOCK"`) revisado: 1065 entradas, **100% tráfego local normal** (gateway `192.168.15.1` e vizinhos `fe80::/10` fazendo descoberta/broadcast) — zero indício de atacante externo.

## Achado 4 (incidente real durante a correção): mapa BPF do net_guard tem capacidade fixa ~1024

Ao tentar carregar a lista [Spamhaus DROP](https://www.spamhaus.org/drop/drop.txt) (1679 blocos CIDR, lista curada de netblocks sequestrados/usados por crime organizado — não é lista ruidosa, é feita especificamente pra bloqueio de borda) no `blocklist.conf` do `net_guard`:

```
net_guard[...]: failed to update blocklist for 192.94.240.0/24: No space left on device
```

Sempre no mesmo bloco (linha ~1038 do arquivo = ~1026ª entrada de IP), a cada tentativa. **Pior do que "ignora o resto"**: o processo trata isso como erro fatal e **sai** — systemd reinicia (`Restart=on-failure`, `RestartSec=2`), o processo tenta carregar o arquivo inteiro de novo, falha exatamente no mesmo ponto, sai de novo. Loop de crash infinito (`activating (auto-restart)` permanente), nunca chegando a `active (running)`.

**Risco real**: durante o loop, `net_guard` não fica estável — não dá pra assumir que o enforcement dele está ativo de forma confiável nesse estado (mesmo que o hook `restrict_connect` antigo pudesse sobreviver goroutine a goroutine entre tentativas, não é algo pra confiar). Confirmado via `sudo bpftool prog list`: `restrict_filesystems` nunca caiu (hook independente, carregado antes do parsing da blocklist), mas `restrict_connect` só voltou a um estado limpo (novo `prog id`, novo `loaded_at`) depois da correção.

**Correção**: cortar a lista pra 1000 entradas totais (999 do Spamhaus + a `1.1.1.1` já existente), margem confortável abaixo do limite observado. Confirmado estável: `NRestarts=0`, log terminando em `net_guard active, monitoring outbound IPv4 connections.`, `restrict_connect` com timestamp novo batendo com o restart bem-sucedido.

**Lição pra qualquer ferramenta própria que carregue dado externo num mapa BPF**: capacidade de mapa costuma ser fixa em tempo de compilação (`max_entries`), e falhar ao atingir o limite pode significar **crash total do processo**, não degradação graciosa (ex.: logar e pular a entrada excedente). Antes de alimentar uma lista externa grande, teste o tamanho real que o mapa aguenta — não assuma que "mais dados" é sempre seguro só porque o formato do arquivo está correto.

## Achado 5: UFW aceitava mDNS/SSDP de entrada por padrão do próprio template

`/etc/ufw/before.rules` (e o equivalente IPv6, `before6.rules`) tem, por padrão do próprio UFW — não algo que o usuário adicionou — duas regras fixas que aceitam entrada multicast independente da política configurada:

```
-A ufw-before-input -p udp -d 224.0.0.251 --dport 5353 -j ACCEPT   # mDNS
-A ufw-before-input -p udp -d 239.255.255.250 --dport 1900 -j ACCEPT  # SSDP/UPnP
```

Como `avahi-daemon` já está desabilitado nesta máquina, nada responde nessas portas hoje — mas a porta continuava aceita no firewall, dependendo só da ausência de um listener pra não ser descoberta. Comentadas as quatro linhas (IPv4 + IPv6) diretamente nos arquivos de template, `ufw reload` aplicado sem erro. Agora o bloqueio é explícito, não depende de "nada estar escutando".

**Pitfall operacional (não de segurança) encontrado nesse passo**: colar um comando longo com `&&` encadeado no terminal do usuário pode ser quebrado em múltiplos comandos separados pelo soft-wrap da própria exibição, causando erros confusos (`cp: missing file operand`, tentativa de *executar* um path de arquivo como comando). Resolvido escrevendo um script e entregando só `bash /caminho/script.sh` — ver nota já registrada em memória do projeto sobre isso.

## Checklist reutilizável (pra próxima auditoria deste tipo)

- [ ] `ufw status verbose` — política padrão certa, sem `ALLOW IN` inesperado
- [ ] `journalctl -k --grep "UFW BLOCK"` — origem dos bloqueios é externa de verdade ou só ruído de LAN?
- [ ] `grep -n "5353\|1900" /etc/ufw/before*.rules` — mDNS/SSDP comentados se não usa discovery de rede (são aceitos por padrão do próprio template do UFW, independente da política configurada)
- [ ] `cat /etc/opensnitchd/default-config.json` — `DefaultAction` é `deny` (não `allow`)? `InterceptUnknown` é `true`?
- [ ] `ls /etc/opensnitchd/rules/` — existem regras permanentes pras ferramentas de automação que rodam sem humano pra clicar em popup?
- [ ] `cat /etc/opensnitchd/network_aliases.json` — existe, tem os IPs próprios conhecidos?
- [ ] `sudo bpftool prog list | grep -A1 restrict_` (ou equivalente pra qualquer enforcement BPF-LSM próprio) — hooks ativos, `loaded_at` recente/consistente com o boot ou último restart esperado, sem sinal de crash loop
- [ ] `systemctl show <unit> -p NRestarts` pra qualquer daemon de enforcement próprio — `NRestarts` alto ou crescendo é sinal de crash loop mesmo que o `systemctl status` pareça "ok" num snapshot único

## Fontes

- [OpenSnitch Wiki — Configurations](https://github.com/evilsocket/opensnitch/wiki/Configurations)
- [OpenSnitch Wiki — Rules](https://github.com/evilsocket/opensnitch/wiki/Rules)
- [`daemon/data/network_aliases.json` — formato oficial](https://github.com/evilsocket/opensnitch/blob/master/daemon/data/network_aliases.json)
- [Spamhaus DROP List](https://www.spamhaus.org/drop/drop.txt) / [Spamhaus DROP FAQ](https://www.spamhaus.org/faqs/do-not-route-or-peer-drop/)
