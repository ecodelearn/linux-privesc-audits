# linux-privesc-audits

Documentação detalhada de vulnerabilidades locais de escalação de privilégio em daemons de sistema (systemd e afins) em uso pessoal de desktop Linux, com fontes, análise de impacto, passos de mitigação reproduzíveis e a metodologia de auditoria usada para verificar exploração prévia.

O objetivo não é só "aplicar o patch e seguir" — é registrar *por que* o bug importa, *como* mitigar sem depender só de uma atualização de pacote, e *como auditar* uma máquina já em uso para confirmar que ela não foi alvo antes da correção.

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

## Aviso

Este repositório é para fins educacionais e de hardening defensivo. Os exemplos foram generalizados a partir de auditorias reais, mas identificadores específicos de máquina (hostname, IP, etc.) foram removidos.
