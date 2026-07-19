#!/usr/bin/env bash
# Auditoria genérica de superfície de ataque IPC no systemd, complementar às
# auditorias pós-fato específicas de cada CVE neste repo. Cobre duas frentes:
#   1. CVEs conhecidas nos pacotes instalados (via arch-audit, se disponível)
#   2. Sockets ativos de famílias "opt-in ligado por padrão" que costumam não
#      ser usadas em desktop pessoal (VM/container, sysext, storage, ssh local)
#
# Ver docs/systemd-attack-surface-reduction.md para a metodologia completa.
# Somente leitura — não altera nada. Requer: systemd, pacman.

set -uo pipefail

section() { printf '\n=== %s ===\n' "$1"; }

section "Frente 1: CVEs conhecidas em pacotes instalados (arch-audit)"
if command -v arch-audit >/dev/null 2>&1; then
    arch-audit
else
    echo "arch-audit não instalado. Rode: sudo pacman -S arch-audit"
fi

section "Frente 2: todos os sockets ativos agora"
systemctl list-sockets --no-pager 2>&1

section "SocketMode de cada socket carregado (0666/0777 = qualquer usuário local conecta)"
for u in $(systemctl list-sockets --no-pager --no-legend --all 2>/dev/null | awk '{print $2}' | sort -u); do
    mode=$(systemctl cat "$u" 2>/dev/null | grep -i '^SocketMode=' | tail -1)
    [ -n "$mode" ] && echo "$u: $mode"
done

section "Família VM/container (machined + importd) — em uso?"
systemctl is-active systemd-machined.socket systemd-importd.socket 2>&1
echo "Máquinas registradas / imagens importadas (esperado vazio se não usa):"
ls /run/systemd/machine/ 2>/dev/null
ls /var/lib/machines/ 2>/dev/null || echo "(sem permissão de leitura — rode como root para checar de fato, ou aceite ausência de evidência de uso)"

section "Família system extensions (sysext/confext) — em uso?"
systemctl is-active systemd-sysext.socket 2>&1
ls -la /etc/extensions /var/lib/extensions 2>&1

section "Família storage/imagem de disco (varlink) — em uso?"
systemctl is-active systemd-storage-block.socket systemd-storage-fs.socket 2>&1
echo "Se você não usa systemd-dissect/portablectl/build de imagem de sistema, isso é candidato a mask."

section "SSH local sem rede (systemd-ssh-generator, systemd >=256) — em uso?"
systemctl is-active sshd-unix-local.socket 2>&1
echo "Gerado incondicionalmente a cada boot desde systemd 256, mesmo com sshd.service desabilitado."
echo "Se você não usa SSH via AF_UNIX/AF_VSOCK para containers/VMs locais, é candidato a mask."

section "Autostart de sessão (.desktop -> systemd --user, via uwsm/wayland-session-xdg-autostart) — em uso?"
echo "Se a sessão gráfica usa uwsm (ou qualquer session manager que amarre"
echo "xdg-desktop-autostart.target ao ciclo de vida da sessão), TODO .desktop em"
echo "/etc/xdg/autostart e ~/.config/autostart vira 'systemctl --user' unit sozinho"
echo "a cada login -- inclusive um .desktop malicioso plantado por algo que já"
echo "rode como você, sem precisar de cron nem edição de .bashrc."
systemctl --user is-enabled xdg-desktop-autostart.target 2>&1
echo "Units geradas agora a partir de autostart (esperado: só o que você reconhece):"
systemctl --user list-units 'app-*' --all --no-legend 2>/dev/null
echo "Se não quer que NENHUM .desktop vire unit automaticamente (recomendado se"
echo "você não depende de autostart de sessão pra nada crítico, ex.: gnome-keyring):"
echo "  systemctl --user mask xdg-desktop-autostart.target"

section "Portais de desktop (xdg-desktop-portal e afins) — flatpak/snap em uso?"
if command -v flatpak >/dev/null 2>&1; then
    echo "flatpak instalado -- xdg-document-portal provavelmente em uso de verdade, não mascarar sem checar."
else
    echo "flatpak não instalado -- xdg-document-portal.service é candidato certo a mask (é específico de sandbox Flatpak/Snap)."
fi
systemctl --user is-enabled xdg-document-portal.service xdg-desktop-portal.service \
    xdg-desktop-portal-gtk.service xdg-desktop-portal-hyprland.service \
    xdg-permission-store.service 2>&1
echo "ATENÇÃO antes de mascarar o resto do stack (xdg-desktop-portal/-gtk/-hyprland/permission-store):"
echo "checar 'Required By' de cada app instalado -- diálogo nativo de abrir/salvar"
echo "arquivo em apps Electron/GTK sandboxed e compartilhamento de tela em chamada de"
echo "vídeo no navegador dependem disso. Ex.: pacman -Qi xdg-desktop-portal | grep 'Required By'"

section "NSS/identidade de usuário (userdbd) — NÃO mascarar sem checar isto primeiro"
systemctl is-active systemd-userdbd.socket 2>&1
echo "Módulo 'systemd' referenciado no NSS (se aparecer abaixo, está em uso interno -- não mascarar):"
grep systemd /etc/nsswitch.conf 2>&1

section "As mesmas famílias existem duplicadas na instância --user (não é privesc, mas é superfície)"
echo "A instância 'systemctl --user' roda seus próprios geradores e cria os mesmos"
echo "sockets em paralelo sob /run/user/\$UID/systemd/... -- mascarar a versão de"
echo "sistema NÃO mascara a versão --user. Diferença de risco: o processo do outro"
echo "lado aqui roda como VOCÊ, não como root, e o diretório /run/user/\$UID é 0700"
echo "(só o dono acessa) -- não é escalação de privilégio, mas ainda é superfície"
echo "desnecessária que um processo malicioso já rodando como você poderia abusar."
echo "Ver docs/systemd-attack-surface-reduction.md para a tabela completa de diferenças."
echo
systemctl --user list-sockets --no-pager --all 2>&1 | grep -iE "machined|importd|sysext|storage|ssh" || echo "(nenhuma das famílias rastreadas presente na instância --user)"

section "Verificação cruzada: mascarado no systemd == realmente fora do kernel?"
echo "systemctl pode dizer 'masked' e a unit ainda ter deixado um socket vivo (foi o"
echo "que aconteceu com machined nesta auditoria: mask sem --now não parou o que já"
echo "estava ativo). A prova real é o que o kernel mostra em 'ss', não o que o"
echo "systemd reporta sobre si mesmo. Cruza os dois pra cada unit da família:"
echo
ss_output=$(ss -l 2>&1)
ss_status=$?
if [ "$ss_status" -ne 0 ]; then
    echo "ERRO: 'ss -l' falhou (status $ss_status) -- resultado abaixo não é confiável."
fi
for u in systemd-machined.socket systemd-importd.socket systemd-sysext.socket \
         systemd-storage-block.socket systemd-storage-fs.socket sshd-unix-local.socket; do
    state=$(systemctl show "$u" -p ActiveState --value 2>/dev/null)
    path=$(systemctl cat "$u" 2>/dev/null | grep -i '^ListenStream=' | tail -1 | cut -d= -f2-)
    if [ "$ss_status" -ne 0 ]; then
        live="INDETERMINADO (ss falhou)"
    elif [ -z "$path" ]; then
        live="sem ListenStream= (não é socket de path, pular)"
    elif printf '%s\n' "$ss_output" | grep -qF "$path"; then
        live="AINDA ESCUTANDO no kernel"
    else
        live="não encontrado em ss"
    fi
    printf '%-32s systemctl=%-10s kernel(ss)=%s\n' "$u" "$state" "$live"
done
echo
echo "-- mesma checagem para a instância --user --"
for u in systemd-machined.socket systemd-importd.socket systemd-storage-fs.socket; do
    state=$(systemctl --user show "$u" -p ActiveState --value 2>/dev/null)
    path=$(systemctl --user cat "$u" 2>/dev/null | grep -i '^ListenStream=' | tail -1 | cut -d= -f2-)
    if [ "$ss_status" -ne 0 ]; then
        live="INDETERMINADO (ss falhou)"
    elif [ -z "$path" ]; then
        live="sem ListenStream= (não é socket de path, pular)"
    elif printf '%s\n' "$ss_output" | grep -qF "$path"; then
        live="AINDA ESCUTANDO no kernel"
    else
        live="não encontrado em ss"
    fi
    printf '%-32s systemctl--user=%-10s kernel(ss)=%s\n' "$u" "$state" "$live"
done
echo
echo "Se 'systemctl' disser inactive/masked mas 'kernel(ss)' disser 'AINDA ESCUTANDO',"
echo "o mask não pegou de verdade -- rode: sudo systemctl mask --now <unit>"
echo "(ou, pra instância --user, sem sudo: systemctl --user mask --now <unit>)"
echo
echo "Nota sobre falsos positivos ao ler 'ss' manualmente: sockets de apps de sessão"
echo "(ex.: terminal, navegador, barra de status) também aparecem em 'ss -pl' e são"
echo "normais -- eles pertencem ao SEU usuário (uid 1000) e ficam sob /run/user/1000/"
echo "ou em namespace abstrato ('@...'). O que importa auditar é especificamente os"
echo "sockets de sistema (donos root, sob /run/systemd/, /run/dbus/) que aparecem em"
echo "'systemctl list-sockets' -- não qualquer socket unix que qualquer app abrir."

section "Fim"
echo "Para qualquer item marcado 'candidato a mask' sem uso comprovado:"
echo "  sudo systemctl mask --now <unit>"
echo "mask sozinho NÃO para uma unit já ativa -- sempre use --now ou confirme"
echo "'Active: inactive (dead)' depois, não só 'Loaded: masked'."
