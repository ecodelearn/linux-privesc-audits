# Trocar systemd por outro init system reduz esse tipo de risco?

Avaliação feita no contexto de um CVE de escalação de privilégio local no `systemd-machined` ([CVE-2026-4105](../CVE-2026-4105-systemd-machined/)), para responder à pergunta óbvia: "será que a raiz do problema é o systemd em si, e vale a pena trocar?"

**Resposta curta: não elimina a classe de risco, só troca de fornecedor — e o custo de migração raramente compensa para um desktop pessoal.**

## O que estava em avaliação

- **Artix Linux** — base Arch, com suporte oficial a runit, OpenRC, s6 e dinit no lugar de systemd.
- **Void Linux** — distro independente, runit como init nativo desde a fundação.

Ambas eliminariam o `systemd-machined` (e o resto do systemd) por completo.

## Por que a classe de vulnerabilidade não desaparece

O padrão do CVE-2026-4105 é: **daemon privilegiado, rodando como root, alcançável via IPC por um processo de usuário comum, com uma falha na validação de "esse pedido é legítimo?"**. Isso não é uma peculiaridade do systemd — é a forma como qualquer sistema Unix moderno precisa lidar com gerenciamento de sessão, montagem de dispositivos removíveis, controle de energia, etc. sem dar `root` direto para todo usuário logado.

O ecossistema alternativo a systemd (`elogind` no lugar de `logind`, `seatd` no lugar de gerenciamento de seat integrado, `dinit`/`runit`/`OpenRC` no lugar do gerenciador de serviços) resolve o mesmo problema com os mesmos riscos estruturais — e tem histórico próprio de CVE do mesmo tipo:

- `seatd-launch` (parte do `seatd`, usado em pilhas com `dinit`/`runit`) teve uma vulnerabilidade de escalação de privilégio onde o binário, rodando setuid root, permitia remoção de arquivo arbitrário via um caminho de socket controlado pelo usuário.

Ou seja: trocar não é "eliminar a superfície de ataque", é "trocar por componentes com um histórico de auditoria e adoção muito menor" — o que estatisticamente tende a significar *mais* bugs não descobertos ainda, não menos.

## Custo real da migração (Artix/Void em cima de um setup CachyOS + Hyprland + NVIDIA)

- **Void Linux**: Hyprland não está nos repositórios oficiais (conflito de filosofia de empacotamento) — só via repositório terceiro com binários de CI. Driver NVIDIA proprietário funciona, mas CUDA fica fora do repositório non-free padrão, gerando trabalho extra para qualquer uso que dependa disso.
- **Artix Linux**: por ser baseada em Arch, tem melhor compatibilidade teórica com Hyprland/NVIDIA — mas ainda é uma **troca de distro**, não uma troca de pacote. Todo o setup específico já existente (integração snapper+limine, overrides de suspend/hibernate para NVIDIA, `uwsm` para as slices de sessão do Hyprland, scripts de hardening de rede como `net_guard`/regras nftables por cgroup) foi construído em cima de primitivas systemd e precisaria ser refeito ou substituído por equivalentes, quando existem.
- Ambas exigem reinstalação/migração completa, não um `pacman -Syu` incremental — risco real de quebrar o boot durante a transição, para uma máquina de uso diário.

## Alternativa que captura o benefício real sem o custo

O ganho de segurança que uma migração de init buscaria — menos daemons privilegiados desnecessários alcançáveis por IPC — já é possível dentro do próprio systemd, sem trocar de distro:

- `systemctl mask` em qualquer daemon de sistema não utilizado (exatamente o que foi feito para o `systemd-machined` neste caso).
- Auditoria periódica de `systemctl list-sockets` por `SocketMode=0666`/`0777`.
- `systemd-analyze security <unit>` para pontuar exposição de cada serviço ainda ativo.

Isso reduz a superfície real disponível para um atacante local sem o custo de uma migração de distro inteira.

## Conclusão

Avaliado e descartado para este caso. Documentado aqui para não precisar reavaliar do zero na próxima vez que a pergunta surgir — a menos que o cenário mude (ex.: uma CVE de systemd sem mitigação viável via `mask`, ou um motivo não relacionado a segurança para migrar).
