# Reduzindo superfície de ataque de IPC privilegiado no systemd

Metodologia genérica e reutilizável — não amarrada a uma CVE específica — para responder a pergunta que sempre volta depois de mitigar uma: *"e os outros daemons que eu nem sei que existem?"*

Nasceu da auditoria de [CVE-2026-4105](../CVE-2026-4105-systemd-machined/), mas o padrão se repete: distros baseadas em Arch com systemd recente vêm com uma quantidade crescente de mini-daemons **ativados por socket, ligados por padrão**, para funcionalidades opcionais (VMs, containers, extensões de sistema, imagens portáteis, SSH local sem rede). A maioria nunca é usada por um desktop pessoal comum, mas continua escutando.

## Duas frentes complementares, não uma só

Uma auditoria de "estou vulnerável?" precisa cobrir dois eixos diferentes:

1. **CVEs conhecidas em pacotes já instalados** — coberto por ferramenta automatizada (`arch-audit`), não por leitura manual de changelog.
2. **Superfície ativa mas não usada** — coberto por inspeção de sockets/serviços, já que um daemon pode não ter CVE pública *hoje* e ainda assim ser risco desnecessário amanhã. A defesa aqui não é "esperar o CVE", é "desligar o que não se usa".

## Frente 1 — CVEs em pacotes instalados: `arch-audit`

```sh
sudo pacman -S arch-audit
arch-audit                 # lista pacotes instalados com CVE conhecida, por severidade
arch-audit -u               # só os que têm update disponível corrigindo a CVE
```

Baseado nos dados do [Arch Security Tracker](https://security.archlinux.org/). Rode depois de cada `pacman -Syu`, ou via pacman hook (`/etc/pacman.d/hooks/`) para checar automaticamente depois de toda atualização — não precisa de timer/rede extra além do que já é usado pra atualizar o sistema.

## Frente 2 — Superfície ativa sem uso: famílias conhecidas de "opt-in ligado por padrão"

Não existe forma 100% automática de saber "esse daemon é usado ou não" — cada família tem seu próprio sinal de "está em uso de verdade". As famílias mais comuns encontradas em sistemas Arch/systemd recentes (261.x):

| Família | Sockets/serviços | Sinal de uso real | Se não usa |
|---|---|---|---|
| VM/container registration | `systemd-machined.{socket,service}` | `machinectl list` retorna algo; `/run/systemd/machine/` tem entradas além dos arquivos base | `mask --now` |
| Import/export de imagem | `systemd-importd.{socket,service}` | `/var/lib/machines/` tem imagens baixadas | `mask --now` |
| System extensions | `systemd-sysext.{socket,service}` | `/etc/extensions/` ou `/var/lib/extensions/` existem e têm conteúdo | `mask --now` |
| Storage/imagem de disco (varlink) | `systemd-storage-block.socket`, `systemd-storage-fs.socket` | Uso de `systemd-dissect`, `portablectl`, ou build de imagem de sistema | `mask --now` |
| SSH local sem rede | `sshd-unix-local.socket` (gerado por `systemd-ssh-generator`, systemd ≥256) | Uso deliberado de VSOCK/AF_UNIX SSH pra acessar containers/VMs locais | `mask --now` |
| NSS/identidade de usuário | `systemd-userdbd.socket` | **Quase sempre em uso** — checar `grep systemd /etc/nsswitch.conf`; se o módulo `systemd` estiver listado no `passwd:`/`group:`, é usado internamente (ex.: `DynamicUser=` em outras units) | **Não mascarar** sem entender o impacto — pode quebrar resolução de usuário/grupo |

Comando genérico pra enumerar tudo que está de fato escutando agora (não só instalado/carregado):

```sh
systemctl list-sockets --no-pager
```

E pra ver o `SocketMode=` de cada um (0666/0777 = qualquer usuário local pode conectar — não é automaticamente perigoso, mas é o primeiro filtro pra priorizar o que investigar):

```sh
for u in $(systemctl list-sockets --no-pager --no-legend --all | awk '{print $2}' | sort -u); do
  mode=$(systemctl cat "$u" 2>/dev/null | grep -i '^SocketMode=' | tail -1)
  [ -n "$mode" ] && echo "$u: $mode"
done
```

## Por que `mask --now` e não `mask` sozinho

`systemctl mask` sozinho só impede início *futuro* — se a unit já estava ativa (comum em sockets, que sobem no boot), ela continua escutando até ser parada explicitamente. Isso já nos pegou uma vez nesta auditoria (ver [writeup da CVE-2026-4105](../CVE-2026-4105-systemd-machined/#mitigação)). `mask --now` faz stop+mask numa operação só — use sempre essa forma para daemons já ativos.

```sh
sudo systemctl mask --now <unit>
```

Depois, sempre confirme o estado real, não só o `Loaded`:

```sh
systemctl status <unit> --no-pager   # Active: deve estar "inactive (dead)"
```

### Verificação cruzada com o kernel, não só com o systemd

`systemctl` reporta o que o *próprio systemd* acha do estado da unit — o que já provou ser insuficiente uma vez nesta auditoria (mask sem `--now` deixou o socket vivo enquanto `Loaded: masked` sugeria segurança). A prova definitiva é o que o kernel realmente tem escutando, via `ss`:

```sh
sudo ss -pl | grep <caminho-do-socket>   # ex.: /run/systemd/machine/io.systemd.Machine
```

Vazio = realmente não está escutando. Se aparecer algo mesmo com a unit mascarada, o `mask` não pegou.

**Cuidado ao ler `ss` manualmente**: sockets de aplicativos de sessão comuns (terminal, navegador, barra de status) também aparecem na saída — eles pertencem ao seu próprio usuário (uid do desktop) e vivem sob `/run/user/<uid>/` ou em namespace abstrato (`@...`). Isso é normal e não tem relação com daemons privilegiados. O que importa auditar são especificamente os sockets listados em `systemctl list-sockets` (sistema, dono root, sob `/run/systemd/` ou `/run/dbus/`) — não qualquer socket unix que qualquer processo abrir. `scripts/systemd-surface-audit.sh` automatiza esse cruzamento para as famílias já catalogadas.

## A instância `--user` gera os mesmos sockets em paralelo — e isso muda o risco, não dobra ele

Cada família de socket coberta acima (`machined`, `importd`, `sysext`, `storage providers`) também existe **duplicada dentro da sua própria instância `systemctl --user`**, sob `/run/user/<uid>/systemd/...`, independente da instância de sistema (`/run/systemd/...`). Mascarar a unit no manager de sistema **não** mascara a cópia da instância `--user` — são unit files e processos completamente separados. Confirmado nesta auditoria: depois de mascarar `systemd-importd.socket`/`systemd-storage-fs.socket`/`systemd-machined.socket` no sistema, os três continuavam escutando sob `/run/user/1000/systemd/...` até serem mascarados separadamente com `systemctl --user mask --now`.

A pergunta natural é: isso é o mesmo risco de privilege escalation? **Não, estruturalmente não** — e vale entender por quê, porque é fácil confundir "roda com `--user`" com "é seguro" ou com "é exploração de privilégio", quando na prática são coisas diferentes dependendo de quem está do outro lado do socket:

| | Instância de sistema (`/run/systemd/...`) | Instância `--user` (`/run/user/<uid>/systemd/...`) |
|---|---|---|
| Processo do outro lado do socket | root | o próprio usuário dono da sessão |
| Isolamento do socket | `SocketMode=0666` — qualquer usuário local conecta | diretório `/run/user/<uid>` é `0700`; socket é `0600` — só o dono acessa |
| O que um bug de lógica ali permite | escalar de usuário sem privilégio pra **root** | fazer, no máximo, algo que você **já pode fazer como você mesmo** |
| Por isso é... | escalação de privilégio real (é o caso do CVE-2026-4105) | superfície desnecessária, mas não cruza fronteira de privilégio |

Ainda vale mascarar a versão `--user` do que não é usado — reduz o que um processo malicioso já rodando como você (ex.: uma extensão de navegador comprometida, um pacote AUR malicioso) conseguiria abusar dentro da sua própria sessão. Mas não é a mesma urgência que a versão de sistema, e tratar as duas como equivalentes leva a alarme desproporcional.

```sh
systemctl --user mask --now systemd-importd.socket systemd-importd.service \
                             systemd-storage-fs.socket \
                             systemd-machined.socket systemd-machined.service
```

Não precisa de `sudo` — é a sua própria instância de usuário.

## O que isso não resolve

Mascarar o que não é usado reduz a superfície, mas não é uma defesa contra CVE em algo que você *precisa* manter ativo (ex.: `NetworkManager`, `polkit`, `dbus-broker`). Para esses, a defesa é a Frente 1 (`arch-audit` + atualização) combinada com hardening de unit (`systemd-analyze security <unit>`, ver [writeup principal](../CVE-2026-4105-systemd-machined/#hardening-geral-complementar)) — não existe "desligar" para o que é essencial ao desktop funcionar.
