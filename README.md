# linux-privesc-audits

Documentação detalhada de vulnerabilidades locais de escalação de privilégio em daemons de sistema (systemd e afins) em uso pessoal de desktop Linux, com fontes, análise de impacto, passos de mitigação reproduzíveis e a metodologia de auditoria usada para verificar exploração prévia.

O objetivo não é só "aplicar o patch e seguir" — é registrar *por que* o bug importa, *como* mitigar sem depender só de uma atualização de pacote, e *como auditar* uma máquina já em uso para confirmar que ela não foi alvo antes da correção.

O conteúdo principal é em português, mas entradas mais recentes vêm ganhando uma versão em inglês (`README.en.md` na mesma pasta) pra facilitar reuso por outras comunidades — ver a partir de [`audits/2026-07-19-desktop-surface-review/`](./audits/2026-07-19-desktop-surface-review/).

## Índice

| Data | CVE | Componente | Severidade | Status |
|------|-----|------------|------------|--------|
| 2026-07-17 | [CVE-2026-4105](./CVE-2026-4105-systemd-machined/) | systemd-machined | CVSS 6.7 (Medium) | Mitigado (mask + stop) |

## Metodologia geral

Cada entrada segue a mesma estrutura:

1. **O que é o bug** — descrição técnica, vetor de ataque, versões afetadas, fontes primárias.
2. **Por que importa nesse contexto** — nem todo CVE de "root local" é urgente; a análise cobre se o componente vulnerável está de fato em uso.
3. **Mitigação** — comandos reproduzíveis, preferindo *remover a superfície de ataque* (mascarar/desligar o que não é usado) a confiar só em esperar o patch.
4. **Auditoria pós-fato** — como verificar, com o que já está disponível no sistema (journal, `pacman -Qkk` ou equivalente, listas de socket/SUID/login), se a falha foi explorada antes da correção.

Veja também:

- [`docs/init-system-alternatives.md`](./docs/init-system-alternatives.md) — avaliação de se trocar de init system (systemd → runit/dinit/OpenRC via Artix ou Void) reduz essa classe de risco. Resposta curta: não elimina, só muda de fornecedor, e o custo de migração costuma não compensar para uso pessoal de desktop.
- [`docs/systemd-attack-surface-reduction.md`](./docs/systemd-attack-surface-reduction.md) — metodologia genérica e reutilizável (não amarrada a uma CVE) para mapear e reduzir a superfície de daemons IPC privilegiados ativados por padrão, incluindo CVEs conhecidas via `arch-audit`.
- [`scripts/systemd-surface-audit.sh`](./scripts/systemd-surface-audit.sh) — script de auditoria read-only que implementa essa metodologia.
- [`scripts/systemd-surface-audit.service` / `.timer`](./scripts/) — units `systemctl --user` prontas pra agendar o script acima rodando toda semana, sem precisar de cron nem de sudo. Ver seção "Agendamento" em [`docs/systemd-attack-surface-reduction.md`](./docs/systemd-attack-surface-reduction.md).

## Outras auditorias

Além de CVEs específicas, o repo também guarda auditorias de configuração pontuais — checar se algo que já estava instalado (firewall, controle de saída por aplicação) está de fato configurado e funcionando como deveria, não só presente:

- [`audits/2026-07-17-firewall-opensnitch-netguard/`](./audits/2026-07-17-firewall-opensnitch-netguard/) — UFW, opensnitch (achado: rodava com `DefaultAction: allow`, sem enforcement real) e um incidente real de crash-loop por limite de capacidade de mapa BPF ao carregar uma lista de bloqueio grande demais.
- [`audits/2026-07-19-desktop-surface-review/`](./audits/2026-07-19-desktop-surface-review/) ([English](./audits/2026-07-19-desktop-surface-review/README.en.md)) — mecanismo do `uwsm` que converte autostart `.desktop` em unit `systemd --user` sozinho (não documentado antes neste repo), `sshd-unix-local.socket` ativo apesar de `sshd.service` disabled, stack `xdg-desktop-portal` mascarado com trade-off explícito, processo órfão de root rastreado até a causa real via journal, avaliação (não mitigação) do isolamento de GPU NVIDIA, e auditoria direta do kernel confirmando que só os 2 hooks LSM eBPF do `net_guard` existem (sem programa de terceiros, sem persistência via bpffs).

## Estudos de arquitetura

Além das auditorias de CVE, o repo também guarda estudos de design de ferramentas de segurança relevantes — não são vulnerabilidades, são dissecações de "como fazer certo":

- [`research/kubearmor-bpf-lsm/`](./research/kubearmor-bpf-lsm/) — leitura guiada do enforcement BPF-LSM real do [KubeArmor](https://github.com/kubearmor/kubearmor) (hooks usados, como evitam TOCTOU, CO-RE na prática, design de map-of-maps por container), com referências ao código-fonte exato lido.

## Aviso

Este repositório é para fins educacionais e de hardening defensivo. Os exemplos foram generalizados a partir de auditorias reais, mas identificadores específicos de máquina (hostname, IP, etc.) foram removidos.
