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

section "NSS/identidade de usuário (userdbd) — NÃO mascarar sem checar isto primeiro"
systemctl is-active systemd-userdbd.socket 2>&1
echo "Módulo 'systemd' referenciado no NSS (se aparecer abaixo, está em uso interno -- não mascarar):"
grep systemd /etc/nsswitch.conf 2>&1

section "Fim"
echo "Para qualquer item marcado 'candidato a mask' sem uso comprovado:"
echo "  sudo systemctl mask --now <unit>"
echo "mask sozinho NÃO para uma unit já ativa -- sempre use --now ou confirme"
echo "'Active: inactive (dead)' depois, não só 'Loaded: masked'."
