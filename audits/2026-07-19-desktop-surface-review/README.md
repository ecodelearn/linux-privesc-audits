# Auditoria: autostart, systemd --user, SSH local, portais e isolamento de GPU (2026-07-19)

*[Read this in English](./README.en.md)*

Varredura ampla pedida como "isso é coisa de invasão?" sobre `/etc/xdg/autostart`, que puxou o fio até um mecanismo inteiro não documentado ainda neste repo: o `uwsm` (Universal Wayland Session Manager) liga qualquer `.desktop` de autostart — sistema ou usuário — à instância `systemctl --user` da sessão. Complementa [`docs/systemd-attack-surface-reduction.md`](../../docs/systemd-attack-surface-reduction.md) (que já cobria `sshd-unix-local.socket` como candidato a mask) e a [auditoria de firewall/opensnitch/net_guard](../2026-07-17-firewall-opensnitch-netguard/) (portas/egress, não repetido aqui em detalhe, só reconfirmado).

## Achado 1: `.desktop` de autostart vira `systemd --user` service automaticamente (uwsm)

Hyprland por si só não lê `/etc/xdg/autostart`. Mas esta máquina usa [`uwsm`](https://man.archlinux.org/man/uwsm.1) (Universal Wayland Session Manager) pra gerenciar a sessão Wayland, e o `uwsm` amarra [`xdg-desktop-autostart.target`](https://www.freedesktop.org/software/systemd/man/latest/systemd.special.html) (via `wayland-session-xdg-autostart@.target`, `BindsTo=`/`Before=` em cadeia) ao ciclo de vida da sessão gráfica. Na prática:

```
systemctl --user list-units 'app-*' --all
```

mostra `app-picom@autostart.service`, `app-gnome-keyring-pkcs11@autostart.service`, `app-cachyos-hello@autostart.service`, `app-remmina-applet@autostart.service` etc. — gerados a partir de `/etc/xdg/autostart/*.desktop` **e** `~/.config/autostart/*.desktop` a cada login, sem precisar de GNOME/KDE completo.

Isso importa porque é um vetor de persistência real e nada óbvio: qualquer `.desktop` malicioso solto em `~/.config/autostart` roda silenciosamente a cada login, sem precisar de cron, systemd unit própria nem entrada em `.bashrc`. Nesta auditoria os arquivos existentes foram todos verificados como legítimos (pacote dono confirmado via `pacman -Qo`, ou instalador de primeiro-uso conhecido — `cachyos-hello`, `remmina-applet`), mas o mecanismo em si merece registro porque não estava documentado.

**Decisão de mitigação** — não mascarar unit por unit (não fecha a porta pra um `.desktop` novo), mascarar o gatilho:

```
systemctl --user mask xdg-desktop-autostart.target
```

Isso é diferente de mascarar `systemd --user` inteiro (não dá, nem faria sentido — no uwsm/Hyprland, `systemd --user` é a espinha dorsal da sessão: cada terminal, cada aba de app roda como scope/slice dele). O alvo é só a ponte `.desktop → systemd unit`.

**Trade-off aceito conscientemente**: isso também impede o autostart automático do `gnome-keyring` (usado por `git`/`gh`/`claude-desktop`/`libsecret` pra credenciais). Se algum desses passar a reclamar de token/senha não encontrado, a correção é subir o keyring manualmente via `exec-once` no `hyprland.conf`, não desfazer o mask.

## Achado 2: `sshd-unix-local.socket` ativo mesmo com `sshd.service` disabled — aplicação do achado já previsto no script deste repo

`scripts/systemd-surface-audit.sh` já sinalizava esta família ("SSH local sem rede ([`systemd-ssh-generator`](https://www.freedesktop.org/software/systemd/man/latest/systemd-ssh-generator.html), systemd >=256)") como candidata a mask, mas não tinha sido aplicado ainda nesta máquina. Confirmado hoje: `sshd.service` estava `disabled`/`inactive` (nunca respondeu na porta 22), mas `sshd-unix-local.socket` — gerado incondicionalmente por `systemd-ssh-generator` a cada boot, independente do `sshd.service` — estava `active (listening)` em `/run/ssh-unix-local/socket` desde o boot.

Não é exposição de rede (é socket `AF_UNIX` local), mas é superfície que ninguém aqui usa (sem containers/VMs locais dependendo de SSH via socket Unix). Mascarado junto com toda a família:

```
systemctl mask sshd.service sshd@.service sshdgenkeys.service ssh-access.target sshd-unix-local.socket
systemctl stop sshd-unix-local.socket   # mask sozinho não para o que já estava ativo
```

Reforça a lição já registrada no script: **`mask` sem `--now`/`stop` não para uma unit já ativa** — só impede reativação futura.

## Achado 3: Samba — não instalado, nada a mascarar

`pacman -Qs samba` vazio, `smb.service`/`smbd.service` inexistentes (`not-found`). Registrado só pra fechar o loop da pergunta original — não é um "achado", é ausência confirmada.

## Achado 4: DNS/`resolved`/`networkd` — limpo; um bug real (não segurança) documentado e deixado como está por decisão do usuário

Cadeia completa auditada: `resolvectl status`, `/etc/resolv.conf`, drop-ins de `/etc/systemd/resolved.conf.d`, `/etc/systemd/network/20-wired.network`, quem escuta na porta 53 (`ss` → só `systemd-resolved`, dois stubs oficiais e documentados do próprio systemd — `127.0.0.53` full-stub, `127.0.0.54` modo *proxy* sem DNSSEC/cache, confirmado hardcoded no binário via `strings` + [`man resolved.conf`](https://www.freedesktop.org/software/systemd/man/latest/resolved.conf.html), não é nada injetado). `NetworkManager` inativo, sem conflito com `networkd`. `FallbackDNS` é o default de fábrica (Quad9/Cloudflare/Google), `LLMNR`/`mDNS` desligados.

Único achado real: `/etc/hosts` linha 7 tem `127.0.1.1  $onlyletther` — variável de template (`$hostname`) nunca interpolada por algum script/instalador, não o hostname de verdade. O próprio `systemd-resolved` já loga isso (`hostname "$onlyletther" is not valid, ignoring`). Inofensivo — usuário decidiu deixar como está por não fazer diferença numa máquina desktop sem necessidade de resolver esse nome. Registrado aqui só pra não ser re-descoberto do zero numa auditoria futura achando que é sinal de algo.

## Achado 5: Portas — reconfirmação, nada novo além do que já estava em [`../2026-07-17-firewall-opensnitch-netguard/`](../2026-07-17-firewall-opensnitch-netguard/)

`ss -tulnp`: só os dois stubs do `resolved` (loopback), DHCPv6 client (`systemd-networkd`, link-local, porta 546 é a porta padrão do protocolo) e uma porta UDP efêmera do Firefox (WebRTC). Nenhuma porta TCP exposta. `ufw status verbose` reconfirma `default deny incoming` e as 21 regras de bloqueio de saída pra portas clássicas de trojan (NetBus, Back Orifice, SubSeven, Metasploit 4444, IRC botnet 6667, RDP, VNC, SMB) já documentadas na auditoria anterior — sem regra `ALLOW IN` inesperada.

## Achado 6: processo órfão rodando como root rastreado até a causa exata via `journalctl` (metodologia, não incidente)

`ps aux` mostrou dois pares `dbus-daemon --session` + `gnome-keyring-daemon --components=secrets` **rodando como root**, `PPid=1` (órfãos, sem parent rastreável em `/proc`). Isso é padrão clássico de "algo suspeito" — mas antes de agir, cross-check no journal pelo horário exato de start:

```
journalctl --since "<hora-1min>" --until "<hora+1min>" | grep -v net_guard
```

revelou a causa exata, com PID e comando de quem pediu:

```
dbus-daemon[125008]: Activating service name='org.freedesktop.secrets'
    requested by ':1.0' (uid=0 pid=124989 comm="gh auth token")
```

`gh auth token` rodado como root (não nesta sessão de auditoria — outra sessão `sudo -i` aberta em paralelo) tentou ler o token salvo do GitHub CLI via Secret Service D-Bus API; como root nunca tinha sessão D-Bus própria, o dbus auto-lançou um bus + keyring privados só pra atender aquele pedido pontual, e ninguém fechou depois. Benigno, mas **auditd não tinha o log** (`/var/log/audit/audit.log` inexistente — auditd está rodando mas não gravando onde `ausearch` espera; não investigado a fundo aqui, candidato a achado futuro) — o `journalctl` do dbus-daemon é que salvou a investigação.

**Lição de metodologia**: `PPid=1` sozinho não prova nada (é reparenting normal de daemon órfão, não indício de esconderijo). O journal do serviço que fez a *activation* (não do processo em si) costuma ter o `comm=` de quem pediu, mesmo depois do processo original ter saído.

Processos limpos após identificação (`kill 125008 125010 125150 125152`) — cosmético, não segurança (não voltam sozinhos, só se algo rodar `gh auth token` como root de novo).

## Achado 7: stack `xdg-desktop-portal` mascarado — mas com decisão explícita sobre trade-off, não um "mask tudo"

[`xdg-document-portal.service`](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.Documents.html) (acesso a arquivo fora do sandbox pra Flatpak/Snap) confirmado órfão de verdade — `flatpak` não está instalado nesta máquina (`which flatpak` vazio), então nada usa esse componente especificamente. Mascarado sem ressalva.

O resto do stack (`xdg-desktop-portal.service`, `-gtk`, `-hyprland`, `xdg-permission-store.service`) **tem dependência reversa real e ativa**: `pacman -Qi xdg-desktop-portal` mostra `Required By: claude-desktop xdg-desktop-portal-gtk xdg-desktop-portal-hyprland`, e `xdg-desktop-portal-hyprland` tem `Required By: cachyos-hypr-noctalia` (a shell do Hyprland em uso). Isso cobre diálogo nativo de abrir/salvar arquivo (Claude Desktop), captura de tela/compartilhamento de tela em chamada de vídeo pelo Firefox, e possivelmente screenshot/wallpaper picker do Noctalia. Mascarado só depois de confirmação explícita do usuário aceitando perder essas funções — não é superfície de rede (tudo D-Bus local), então o ganho é redução de processo/API disponível pra qualquer coisa rodando com o mesmo UID, não fechamento de porta.

```
systemctl --user mask xdg-document-portal.service                                    # órfão real
systemctl --user mask xdg-desktop-portal.service xdg-desktop-portal-gtk.service \
    xdg-desktop-portal-hyprland.service xdg-permission-store.service                  # trade-off aceito
```

Se o Claude Desktop parar de abrir diálogo nativo de arquivo, ou o Noctalia perder screenshot, é isso — reverter com `systemctl --user unmask <unit>`.

## Achado 8: NVIDIA — `/dev/nvidia*` em `666` e Compute Mode `Default`; avaliado e decidido não mitigar

```
crw-rw-rw- root root /dev/nvidia0 /dev/nvidiactl /dev/nvidia-modeset /dev/nvidia-uvm /dev/nvidia-uvm-tools
nvidia-smi --query-gpu=compute_mode  →  Default
```

Isso é o default de fábrica ([Compute Mode `Default` vs `Exclusive_Process`, docs oficiais NVIDIA](https://docs.nvidia.com/deploy/mps/index.html)) do driver proprietário em desktop Linux (nenhuma regra `udev` customizada encontrada em `/etc/udev/rules.d`), não algo alterado. `Default` compute mode não garante isolamento estrito de memória de GPU entre processos concorrentes — classe de risco real, mas documentada pela própria NVIDIA como relevante principalmente pra GPU compartilhada multi-tenant (nuvem, laboratório).

**Por que não mitigado aqui**: `awk -F: '$3>=1000 && $3<60000'` em `/etc/passwd` confirma **uma única conta de login** (`ecode`, já no grupo `video`). Sem segunda conta local, não existe "outro usuário" pra isolar de — apertar pra `660 root:video` via regra `udev` própria não fecharia superfície nenhuma que já não esteja fechada pelo simples fato de só existir um usuário com shell nesta máquina. Registrado como decisão consciente, não como pendência: se algum dia esta máquina ganhar uma segunda conta de login, revisitar este achado primeiro.

## Achado 9: LSM eBPF — só os 2 hooks do `net_guard`, sem programa de terceiros, sem persistência via bpffs

Auditoria direta do kernel, não confiando em "o `systemctl status` diz que só o `net_guard` existe":

```
cat /sys/kernel/security/lsm                    # confirma 'bpf' entre os LSMs habilitados
bpftool prog list | grep '^\S*: lsm'             # filtra só programas tipo LSM, kernel inteiro
find /sys/fs/bpf -mindepth 1                     # objetos pinados independentes de processo
```

Resultado: exatamente dois programas `lsm` no kernel inteiro — `restrict_filesystems` e `restrict_connect` — ambos `loaded_at` no horário de boot (12:34:15), dono `uid 0`, **sem duplicata** (confirma que o crash-loop documentado na [auditoria de 17/07](../2026-07-17-firewall-opensnitch-netguard/) continua resolvido — um load só, não vários por reinício). `find /sys/fs/bpf` vazio: nenhum programa/map pinado sobrevivendo fora do ciclo de vida normal do processo — técnica clássica de persistência de rootkit via eBPF (programa pinado continua ativo mesmo se o processo que carregou morrer, sem PID pra rastrear) descartada.

Corroboração extra, não só "existe, então confio": os maps por trás de `restrict_connect` (`bpftool map show id <n>`) são `blocked_ips` (LPM trie, `max_entries 1024`) e `events` (ringbuf) — o `1024` bate exatamente com o limite de capacidade que causou o crash-loop documentado no Achado 4 da auditoria de 17/07, e o ringbuf é o canal por trás das linhas `net_guard[492]: allow/deny ...` já vistas no journal. Não é só "um programa chamado net_guard existe", é "os dados internos dele batem com o que já se sabia sobre essa ferramenta".

Achado colateral, não é problema: o único programa BPF "estranho" à primeira vista (`cgroup_sysctl name sysctl_monitor`, `uid 977`) é do próprio `systemd-networkd` (`getent passwd 977` → `systemd-network`), feature interna dele. Os vários `sd_fw_egress`/`sd_fw_ingress`/`sd_devices` (`cgroup_skb`/`cgroup_device`) são o systemd criando um programa por scope com `IPAddressAllow=`/`DeviceAllow=` — um cluster novo por sessão de terminal/`sudo -i` aberta, comportamento normal desde systemd 235+.

## Achado 10: verificação final pós-mitigação — nada novo, nenhuma técnica de ocultação encontrada

Depois de aplicar todas as mitigações acima (Achados 1, 2, 7), reauditoria pontual pra confirmar que nada ficou preso nem apareceu de novo — não basta mitigar uma vez, vale reconferir com o sistema já no estado final:

```
find /sys/fs/bpf -mindepth 1                                  # bpffs: continua vazio
bpftool prog list | grep -c '^[0-9]*:'                        # total de programas BPF estável (48)
bpftool prog list | grep '^\S*: lsm'                           # ainda só os 2 do net_guard
```

Duas checagens novas, não cobertas nos achados anteriores — técnicas clássicas de esconder processo malicioso que valem checar sempre que se audita um sistema já em uso, não só depois de uma mitigação pontual:

```
# processo rodando a partir de local tipico de malware (payload solto por script/download)
for p in /proc/[0-9]*; do
  readlink "$p/exe" 2>/dev/null | grep -qE '^/(tmp|dev/shm|var/tmp)/' && echo "$p"
done

# binario deletado do disco mas ainda rodando em memoria (esconde de "ls", nao de /proc)
for p in /proc/[0-9]*; do
  readlink "$p/exe" 2>/dev/null | grep -q '(deleted)' && echo "$p"
done
```

Ambas vazias. Revisão final de todo `ps -eo ... | grep -v <daemons de kernel conhecidos>` também não trouxe nenhum processo `root` fora do que já estava mapeado nos achados anteriores (mesmos PIDs de `net_guard`, `opensnitchd`, `fail2ban`, `ly-dm`, sessões `sudo -i` já identificadas). Auditoria fechada sem pendência.

## Checklist reutilizável (pra próxima auditoria deste tipo)

- [ ] `systemctl --user list-units 'app-*' --all` — algum `.desktop` novo/desconhecido em `/etc/xdg/autostart` ou `~/.config/autostart` virou unit?
- [ ] `systemctl --user is-enabled xdg-desktop-autostart.target sshd-unix-local.socket xdg-document-portal.service xdg-desktop-portal.service xdg-desktop-portal-gtk.service xdg-desktop-portal-hyprland.service xdg-permission-store.service` — todos `masked`?
- [ ] `systemctl is-enabled sshd.service sshd@.service sshdgenkeys.service ssh-access.target sshd-unix-local.socket` — todos `masked` a nível de sistema também?
- [ ] `ss -tulnp` — nenhuma porta TCP nova exposta além dos stubs de loopback do `resolved`
- [ ] `resolvectl status` + `cat /etc/hosts` — DNS servers batem com o gateway esperado, sem entrada de `/etc/hosts` nova e não intencional
- [ ] `ps aux` com qualquer processo `root` de nome inesperado — antes de suspeitar, cruzar `journalctl --since/--until` no segundo exato do `START` pra achar o `comm=` de quem ativou (não confiar só em `PPid`, que costuma virar `1` por reparenting normal)
- [ ] `ls -la /dev/nvidia*` + `awk -F: '$3>=1000 && $3<60000' /etc/passwd` — se uma segunda conta de login aparecer, revisitar o Achado 8 (permissão `666` deixa de ser indiferente)
- [ ] `bpftool prog list | grep '^\S*: lsm'` — só os hooks esperados (hoje: `restrict_filesystems` + `restrict_connect` do `net_guard`), sem duplicata (crash-loop) e sem programa de terceiros
- [ ] `find /sys/fs/bpf -mindepth 1` — vazio, ou só objetos que você reconhece; algo pinado e não rastreável a um processo vivo é bandeira vermelha
- [ ] processo rodando a partir de `/tmp`, `/dev/shm` ou `/var/tmp` (`readlink /proc/<pid>/exe`) — local típico de payload solto por script/download
- [ ] binário deletado do disco mas ainda rodando em memória (`readlink /proc/<pid>/exe` termina em `(deleted)`) — esconde de `ls`, não de `/proc`

## Fontes

- [`man resolved.conf`](https://www.freedesktop.org/software/systemd/man/latest/resolved.conf.html) — `127.0.0.53` vs `127.0.0.54` (modo proxy), `DNSStubListenerExtra`
- [`man systemd-ssh-generator`](https://www.freedesktop.org/software/systemd/man/latest/systemd-ssh-generator.html) — `sshd-unix-local.socket` gerado incondicionalmente desde systemd 256
- [`man uwsm`](https://man.archlinux.org/man/uwsm.1) — `wayland-session-xdg-autostart@.target`, integração com `xdg-desktop-autostart.target`
- [XDG Desktop Portal — documentação oficial](https://flatpak.github.io/xdg-desktop-portal/docs/) — papel de cada backend (`-gtk`, `-hyprland`), `xdg-document-portal` específico de sandbox
- [NVIDIA — Multi-Instance GPU / Compute Mode docs](https://docs.nvidia.com/deploy/mps/index.html) — implicações de isolamento do modo `Default` vs `EXCLUSIVE_PROCESS`
- [`bpftool-prog(8)`](https://man.archlinux.org/man/bpftool-prog.8) — listagem e inspeção de programas BPF carregados, incluindo tipo `lsm`
