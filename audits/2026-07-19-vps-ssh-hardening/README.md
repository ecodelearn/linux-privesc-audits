# Auditoria: SSH nas VPS próprias — root por senha exposto e vetor de túnel reverso (2026-07-19)

Motivada por uma pergunta simples ("e a possibilidade de SSH reverso das VPS?") sobre o desktop já endurecido nas auditorias anteriores ([firewall/opensnitch/net_guard](../2026-07-17-firewall-opensnitch-netguard/), [autostart/portais/GPU](../2026-07-19-desktop-surface-review/)) — mas que puxou um achado bem mais grave que o vetor original, nas três VPS que a máquina acessa por SSH: `contabo1`, `contabo2` e `fomentofacil` (porta SSH alternativa `10002`, descoberta/adicionada durante esta mesma auditoria). IPs omitidos de propósito — ver `~/.ssh/config` local pra resolução de host.

## Contexto: por que "SSH reverso" importava aqui

O desktop não expõe `sshd` (mascarado, ver auditoria de 19/07 anterior), então uma VPS comprometida não consegue *iniciar* conexão de volta pro desktop diretamente. O vetor real é outro: se o **desktop** (ou qualquer processo automatizado nele) rodar `ssh -R <porta>:localhost:22 root@contaboN`, isso abre uma conexão de saída — permitida pelo `UFW allow outgoing`, e pro opensnitch é indistinguível de um login normal (o popup mostra processo+IP+porta, não os flags `-R`/`-L`/`-D`). Resultado: a VPS passa a escutar uma porta que devolve acesso ao `sshd` local. Se a VPS for comprometida, quem estiver nela ganha caminho de volta pro desktop sem nunca precisar de uma regra `ALLOW IN` — porque nada "entrou" do ponto de vista do firewall, foi tráfego dentro de uma sessão que o próprio desktop abriu.

O contexto que elevou a prioridade: as duas VPS rodam agentes autônomos (Claude, Codex, Hermes) e crawlers/bots com acesso root direto — superfície de prompt injection real (conteúdo externo não confiável chegando em agente com tool-use). Root + exposição a prompt injection = uma injeção bem-sucedida em qualquer agente já é compromisso total da caixa, sem escalonamento necessário. **Esse problema maior (agentes rodando como root) segue em aberto — não foi mitigado nesta auditoria, só mapeado.** Ver "Pendências" no final.

## Achado 1 (crítico): root aceitava login por senha, exposto pra internet inteira, nas duas VPS

Levantamento (`sshd -T`, teste de alcance externo do próprio desktop via `/dev/tcp`):

| | contabo1 | contabo2 |
|---|---|---|
| `PermitRootLogin` efetivo | `yes` | `yes` |
| `PasswordAuthentication` efetivo | `yes` | `yes` |
| Porta 22 alcançável de fora | confirmado | confirmado |
| Conta `root` tem senha definida | sim (`passwd -S` → `P`) | sim (`passwd -S` → `P`) |

Ou seja: dava pra tentar logar como `root` nas duas caixas só com usuário+senha, de qualquer lugar da internet, sem precisar de chave — alvo clássico de bot de brute-force/credential-stuffing.

Causa raiz diferente em cada uma:
- **contabo1**: `/etc/ssh/sshd_config` principal já tinha `PasswordAuthentication no`, mas `Include /etc/ssh/sshd_config.d/*.conf` (linha 4) vem *antes* dessa diretiva no arquivo. O drop-in `50-cloud-init.conf` (posto pelo cloud-init da própria Contabo) reafirma `PasswordAuthentication yes`. Como o OpenSSH aplica a **primeira ocorrência** de cada diretiva (não a última), o `yes` do cloud-init vencia e o `no` pretendido no arquivo principal nunca chegava a valer.
- **contabo2**: `PasswordAuthentication yes` estava direto no `sshd_config` principal, sem Include conflitante — configuração simplesmente nunca foi endurecida.

**Correção**: criado `/etc/ssh/sshd_config.d/00-hardening.conf` em cada VPS (nome escolhido pra ordenar *antes* de `50-cloud-init.conf` em ordem léxica, garantindo que vença a regra de "primeira ocorrência vale"):

```
PasswordAuthentication no
PermitRootLogin prohibit-password
AllowTcpForwarding no
PermitTunnel no
GatewayPorts no
```

Aplicado com `sshd -t` (valida sintaxe) antes de `systemctl reload sshd` (contabo1) / `systemctl reload ssh` (contabo2 — nomes de unit diferentes, Arch vs Debian) — `reload`, não `restart`, pra não derrubar sessões ativas dos agentes. Confirmado via `sshd -T` pós-reload e reconexão em sessão nova usando só a chave (sem senha disponível) nas duas.

## Achado 2: vetor de túnel SSH reverso fechado — não estava em uso

`AllowTcpForwarding no` + `PermitTunnel no` + `GatewayPorts no` (aplicado junto no Achado 1) fecham a classe inteira: o daemon agora recusa qualquer pedido de `-L`/`-R`/`-D` na conexão, não importa o que o cliente peça. Confirmado com o usuário que forwarding não é usado hoje contra essas VPS (chegou a ser usado no passado, não mais) — login normal, `scp`, `git` via SSH continuam funcionando igual.

## Achado 3: portas de gerência do Docker Swarm expostas em `0.0.0.0` na contabo2 — verificado, UFW bloqueia corretamente

`ss -tulnp` na contabo2 mostrou `dockerd` escutando em `*:2377` (API de gerência do Swarm), `*:7946` (gossip, tcp+udp) e `*:4789` (VXLAN overlay, udp) — todas em todas as interfaces, não só localhost. Isso por si só pareceria crítico (API de Swarm sem auth = RCE se alcançável), mas:

```
ufw status verbose   # default deny incoming, só 22/80/443(+19532 mTLS) liberados
```

Teste real de fora (do desktop, via `/dev/tcp/<IP contabo2>/2377` e `/7946`): **não alcançável**. Diferente do problema clássico "Docker bypassa UFW" (que acontece com porta *publicada* de container via `-p`, que usa DNAT na chain `PREROUTING`/`nat` e pula a chain `INPUT` onde o UFW filtra) — essas portas do Swarm são bind direto do processo `dockerd` no namespace de rede do host, então passam pela `INPUT` normal e o `deny incoming` do UFW se aplica. Nenhum outro container publica porta pro host além do que já passa pelo Traefik (`docker ps --format '{{.Ports}}'` conferido nas duas VPS) — nada a corrigir aqui, registrado como baseline confirmado.

**Pegadinha pra lembrar em auditoria futura**: essa distinção (bind direto do processo vs porta publicada via `-p`/DNAT) é o que decide se o UFW protege ou não. Publicar uma porta nova de container sem checar isso é a forma mais fácil de vazar algo sem perceber, mesmo com UFW "ativo".

## Achado 4 (crítico, mesma classe do Achado 1): fomentofacil.com.br — root+senha exposto, e um controle de acesso que não fazia o que parecia fazer

Terceira VPS, descoberta durante a própria conversa (usuário lembrou da porta 10002, depois localizou IP/credenciais). Diagnóstico:

```
sshd -T | grep -iE "passwordauthentication|permitrootlogin"
  permitrootlogin yes
  passwordauthentication yes
```

`ufw status` confirmou `10002/tcp ALLOW IN Anywhere` — porta SSH alternativa aberta pra internet inteira, com root+senha aceito. **Diferente das outras duas, aqui existia uma tentativa de controle de acesso real que estava sendo derrotada silenciosamente**: `/etc/ssh/sshd_config.d/99-tailscale-root.conf` tem um bloco `Match Address 100.64.0.0/10,fd7a:115c:a1e0::/48` (faixa CGNAT do Tailscale) restringindo `PermitRootLogin prohibit-password` — ou seja, alguém queria que root só entrasse por chave *quando vindo da rede Tailscale*. Mas isso é só o valor dentro do `Match`; fora dele (conexão vinda da internet pública, como a nossa) vale o `PasswordAuthentication yes` global do `50-cloud-init.conf`, que vence por ser lido primeiro entre os drop-ins (mesmo mecanismo do Achado 1). Resultado prático: a intenção de "só Tailscale" nunca protegeu a porta pública — confirmado ao vivo, autenticamos com usuário+senha direto pelo IP público, sem passar pelo Tailscale.

**Complicador**: a chave que o usuário tinha em mãos para essa VPS não era a correta (`Permission denied (publickey,password)` na primeira tentativa) — diferente das outras duas, aqui não dava pra simplesmente desligar `PasswordAuthentication`, ou root ficaria sem nenhum acesso SSH válido (dependente de console de emergência do provedor). Ordem de correção seguida:

1. Gerada chave nova dedicada (`ssh-keygen -t ed25519`, `~/.ssh/fomentofacil_ed25519`, sem passphrase — mesmo padrão das outras duas, pensado pra automação).
2. `authorized_keys` do `root` **substituído** (não só acrescentado) pela chave nova via a sessão autenticada por senha — remove qualquer chave antiga desconhecida que estivesse lá.
3. Login com a chave nova confirmado funcionando **antes** de tocar em `PasswordAuthentication`.
4. Só então aplicado o mesmo `00-hardening.conf` das outras duas (`PasswordAuthentication no`, `PermitRootLogin prohibit-password`, `AllowTcpForwarding no`, `PermitTunnel no`, `GatewayPorts no`) — sorteia antes de `50-cloud-init.conf` na ordem léxica do glob, então vence a regra de primeira ocorrência.
5. Confirmado: chave nova entra, senha antiga agora recusa direto com `Permission denied (publickey)` (nem chega a pedir senha).

O bloco `Match` do Tailscale foi deixado como está — vira redundante (já era `prohibit-password`, igual ao novo global), mas inofensivo manter.

**Nota de higiene de credenciais**: a chave privada antiga (que não funcionou) e as duas senhas candidatas passaram em texto puro pelo chat durante o diagnóstico — tratadas como comprometidas por definição, independente de terem funcionado ou não. A chave já foi apagada do disco sem uso; a senha antiga do `root` nem autentica mais depois da correção acima, então não precisa de rotação adicional além do que já foi feito.

## Achado 5: superfícies não cobertas nesta auditoria, registradas na fomentofacil

Levantamento (`ss -tulnp`, `docker ps`) trouxe contexto que não foi auditado a fundo aqui, só observado:

- **Servidor de e-mail completo rodando na própria VPS**: Postfix (`25/tcp` entrada, `587/tcp` submission) + Dovecot (`110`/`995`, POP3/POP3S) expostos via UFW `ALLOW IN Anywhere`. Superfície clássica de abuso (relay de spam, brute-force de credencial de e-mail) que não foi auditada nesta sessão — candidato a auditoria própria (checar `smtpd_relay_restrictions` do Postfix, `fail2ban` jails pra Dovecot/Postfix, se IMAP/993 está desativado de propósito ou só não configurado).
- **Stack Docker `editais-*`** (Prometheus, Grafana, Alertmanager, node-exporter, Flower/Celery, Postgres) — aparenta ser pipeline de monitoramento de editais públicos, não os agentes autônomos mencionados na motivação original desta auditoria. `grafana` bind em `*:3000` (todas interfaces) mas com `DENY IN` explícito no UFW pra essa porta — checado, não alcançável de fora, mas vale confirmar que ninguém remova essa regra sem perceber a dependência.
- **UFW já tinha uma lista extensa de `DENY IN` por faixa de IP específica** (`47.251.0.0/16`, `8.218.0.0/16`, várias outras) — sinal de que já houve resposta reativa a abuso/scan no passado. Não investigado o motivo/origem de cada uma nesta auditoria.

## Pendências (não resolvidas nesta auditoria, registradas pra não perder o fio)

- **Agentes autônomos (Claude, Codex, Hermes) rodando como root nas VPS**, com exposição a prompt injection via crawlers e `evolution-api` (gateway WhatsApp) alimentando workflows do `n8n`. Esse é o risco de maior impacto do ambiente inteiro — root direto elimina qualquer necessidade de escalonamento de privilégio pós-injeção. Precisa de auditoria própria: usuário não-root dedicado por agente, sandboxing (container com `--cap-drop=ALL`/`no-new-privileges`, ou `DynamicUser=`/`ProtectSystem=strict` se for systemd direto), egress control por processo (equivalente ao `net_guard`/opensnitch do desktop, mas na VPS), e credenciais/API keys segregadas por agente em vez de um ambiente root compartilhado.
- Stack identificada na contabo2 pra contexto da pendência acima: `n8n` (editor+webhook+worker, webhook público via Traefik), `mcp-servers` (stack com Prometheus+Redis próprios — serve tool-calls tipo MCP pros agentes), `evolution-api` (gateway WhatsApp, entrada de conteúdo não confiável), `portainer` (agente+servidor — gerência de todo o Swarm, alvo de alto valor se comprometido), `pgvector`+`postgres` (memória/RAG).
- `auditd` sem log funcional também nas VPS — mesmo gap já registrado no desktop (Achado 6 da [auditoria de 19/07](../2026-07-19-desktop-surface-review/)); sem isso, não dá pra diferenciar exec normal de exec suspeito por linha de comando nem nas VPS.
- Warning do próprio `ssh` nas duas conexões: troca de chave não é post-quantum (`store now, decrypt later`) — não é urgente hoje, mas registrar pra revisitar se/quando os clientes SSH usados suportarem KEX PQ por padrão.

## Checklist reutilizável (pra próxima auditoria deste tipo)

- [ ] `sshd -T | grep -iE "passwordauthentication|permitrootlogin"` em cada host — nunca confiar só no `grep` do arquivo principal, `Include` pode ser sobrescrito por drop-in que carrega antes (regra: primeira ocorrência vence, não a última)
- [ ] `passwd -S root` — conta root tem senha definida? Mesmo com `PasswordAuthentication no`, senha definida é risco residual (ex: console de emergência do provedor, VPN local, etc.)
- [ ] Testar alcance externo de verdade (`timeout 5 bash -c 'cat < /dev/null > /dev/tcp/IP/PORTA'` do lado de fora) em vez de confiar só em `ufw status` — política pode estar certa e ainda assim algo vazar por outro caminho (DNAT de container, bind direto de outro daemon)
- [ ] `sshd -T | grep -iE "allowtcpforwarding|permittunnel|gatewayports"` — se não usa forward/túnel de propósito pra aquele host, travar os três
- [ ] `docker ps --format '{{.Names}}: {{.Ports}}'` em cada host Docker — qualquer porta com `0.0.0.0:X->Y` é candidata a checar alcance externo; porta sem esse prefixo só é visível de dentro da rede docker (mas ainda vale conferir se algum outro container faz proxy pra ela)
- [ ] Se algum processo (não container) faz bind em `0.0.0.0` numa porta alta (ex: API de cluster, Swarm, etc.) — não assumir que "UFW deny incoming" cobre por padrão sem testar; a diferença entre bind direto e porta publicada via `-p`/DNAT decide se o UFW filtra ou não
- [ ] Qualquer agente/processo autônomo com tool-use rodando como root numa VPS pública — tratar como prioridade máxima de mitigação, independente de mais nada nesta lista

## Fontes

- [`man sshd_config`](https://man.openbsd.org/sshd_config) — `Include`, ordem de "primeira ocorrência vence", `PermitRootLogin` (`prohibit-password`/`without-password`), `AllowTcpForwarding`, `GatewayPorts`, `PermitTunnel`
- [Docker Swarm — network ports used](https://docs.docker.com/engine/swarm/swarm-tutorial/#open-protocols-and-ports-between-the-hosts) — 2377/tcp (gerência), 7946/tcp+udp (gossip), 4789/udp (VXLAN overlay)
- [Docker and UFW — known bypass via DNAT](https://github.com/chaifeng/ufw-docker) — por que porta publicada de container (`-p`) pode ignorar a política do UFW mesmo com `deny incoming`, diferente de bind direto de processo no host
