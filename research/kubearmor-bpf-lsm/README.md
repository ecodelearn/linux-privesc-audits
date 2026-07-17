# Dissecando o design de enforcement BPF-LSM do KubeArmor

Estudo de arquitetura — não é uma auditoria de CVE, é uma leitura guiada do código-fonte real de um projeto de enforcement em produção, pra entender como "fazer BPF LSM certo" na prática, antes de escrever hook próprio. Todas as referências de código apontam pro commit `1f22e362be2de94dc7d8bd22e4c2b821aefa153c` de [`kubearmor/kubearmor`](https://github.com/kubearmor/kubearmor) (2026-07-17) — o projeto é ativo, então as linhas podem mudar; use o SHA pra reproduzir exatamente o que foi lido aqui.

## Por que este projeto e não outro

KubeArmor faz **enforcement inline de verdade** (nega antes da operação completar), não só detecção-e-reação como o Falco. Tetragon também faz enforcement inline, mas o KubeArmor tem a vantagem de oferecer um design mais simples de seguir por completo (não depende de um pipeline de política tão grande quanto o do Tetragon/Cilium) e de já ter passado por produção em escala com [lições documentadas em blog](https://kubearmor.io/blog/bpf-lsm-armor) — bom ponto de partida antes de subir pra algo do porte do Tetragon.

## 1. Onde o enforcement acontece: os hooks LSM escolhidos

Dois hooks fazem o trabalho pesado em [`KubeArmor/BPF/enforcer.bpf.c`](https://github.com/kubearmor/kubearmor/blob/1f22e362be2de94dc7d8bd22e4c2b821aefa153c/KubeArmor/BPF/enforcer.bpf.c):

```c
SEC("lsm/bprm_check_security")
int BPF_PROG(enforce_proc, struct linux_binprm *bprm, int ret)
```
Dispara antes de **todo** `execve` — é aqui que regras de "não pode rodar esse binário" são decididas.

```c
SEC("lsm/socket_sendmsg")
int BPF_PROG(enforce_dns, struct socket *sock, struct msghdr *msg, int size)
```
Dispara em todo envio de socket — usado especificamente pra inspecionar payload DNS (porta 53) e aplicar regras de rede por **nome de domínio**, não só IP/porta. Isso é um detalhe interessante: enforcement de rede aqui não é feito no nível de `socket_connect`/`socket_create` (que só veem endereço), e sim inspecionando o conteúdo da mensagem em `socket_sendmsg` pra extrair o nome DNS antes de decidir.

Cada hook retorna `0` (permite) ou `-EPERM` (nega) — é literalmente o valor de retorno da função LSM que vira o valor de retorno da syscall pro processo que tentou a ação. Não tem callback assíncrono, não tem fila — a decisão é sempre síncrona, dentro do próprio hook.

## 2. Como evitam TOCTOU: nunca confiam em ponteiro de userspace

O ponto mais importante pra quem for escrever isso do zero. Em vez de ler o path do binário a partir de argumentos de userspace (que o processo poderia trocar entre o momento da checagem e o momento do uso — a janela de corrida clássica), o hook resolve o path **a partir da própria estrutura do kernel** que o LSM já entregou:

```c
struct path f_path = BPF_CORE_READ(bprm->file, f_path);
if (!prepend_path(&f_path, path_buf))
    return 0;
```

`bprm->file` é o `struct file*` do kernel pro binário que está prestes a executar — já resolvido pelo kernel antes do hook disparar, não uma string que o processo passou. `prepend_path` caminha a cadeia de `dentry`/`vfsmount` (também estruturas de kernel) pra montar o path completo. Isso é exatamente a técnica que o [post da Datadog sobre lições de eBPF em produção](https://www.datadoghq.com/blog/engineering/ebpf-workload-protection-lessons/) recomenda: "Datadog resolves paths entirely from kernel data structures and waits until the kernel has copied user-space content before reading."

## 3. Como lidam com o kernel mudando de versão embaixo dos pés: CO-RE na prática

Exemplo real do hook de DNS, tratando uma struct que teve campo renomeado entre versões de kernel:

```c
// Handle __iov / iov field rename across kernel versions
struct iov_iter___new *iter = (void *)&msg->msg_iter;
if (bpf_core_field_exists(iter->__iov))
{
    bpf_probe_read_kernel(&iov_ptr, sizeof(iov_ptr), &iter->__iov);
}
else
{
    bpf_probe_read_kernel(&iov_ptr, sizeof(iov_ptr), &iter->iov);
}
```

`bpf_core_field_exists()` é uma macro do CO-RE que, em tempo de *load* (não de compilação), checa contra o BTF do kernel rodando se aquele campo existe naquela versão — e o programa se adapta. Isso é literalmente o "compile once, run everywhere" funcionando: um único binário `.o` compilado uma vez roda em kernels com layouts de struct diferentes, porque o libbpf resolve as relocations contra o BTF do host no momento do load, não em tempo de compilação. Sem isso, esse mesmo hook quebraria silenciosamente (ou pior, leria memória errada) em metade dos kernels em produção.

## 4. Como escalam política sem checar arquivo-por-arquivo: map-of-maps por contêiner

Do lado Go ([`KubeArmor/enforcer/bpflsm/mapHelpers.go`](https://github.com/kubearmor/kubearmor/blob/1f22e362be2de94dc7d8bd22e4c2b821aefa153c/KubeArmor/enforcer/bpflsm/mapHelpers.go)):

```go
type NsKey struct {
    PidNS uint32
    MntNS uint32
}
```

A política inteira é um **mapa de mapas**: um mapa externo (`kubearmor_containers` no lado C) chaveado por namespace (PID+mount namespace = identifica um container/processo isolado), cada entrada apontando pra um mapa interno próprio com as regras daquele container especificamente (`ContainerMap[containerID] = ContainerKV{..., Map: im, ...}`, criado via `ebpf.NewMap`). Isso significa: o hook do kernel primeiro resolve "esse processo pertence a qual container", pega o mapa interno certo com uma única lookup, e só então procura a regra — em vez de ter uma tabela gigante global com todo path de todo container prefixado por ID. Escala por isolamento, não por tamanho de tabela.

Dentro do mapa de um container, a resolução de regra não é só "path exato" — tem fallback hierárquico: match exato de path+source primeiro, depois sobe diretório por diretório (`RULE_DIR` + `RULE_RECURSIVE`) checando se algum ancestral do path tem regra recursiva, tudo resolvido com um loop `#pragma unroll` dentro do próprio programa BPF (o verifier exige bound estático em loops, por isso o unroll até um limite fixo de 64 níveis).

## 5. A biblioteca do lado userspace: `cilium/ebpf`, não bcc

O carregamento dos mapas e do programa `.o` (compilado separadamente via clang com suporte a BTF) usa [`github.com/cilium/ebpf`](https://github.com/cilium/ebpf) — a lib Go pura mantida pelo próprio projeto Cilium, usada também pelo Tetragon. Relevante pro seu caso: se for escrever ferramenta de enforcement em Go (como o seu `archguard-go`), essa é a biblioteca de referência, não bcc-python (legado, mais pesado, não CO-RE nativo) nem libbpf em C puro direto (mais controle, mas sem os helpers de tooling Go que o cilium/ebpf já resolve — geração de binding Go a partir do `.bpf.c` compilado, por exemplo os arquivos `enforcer_bpfel.go`/`enforcer_bpfeb.go` no repo são gerados automaticamente por esse toolchain, um pra each-endian).

## Resumo do que vale levar pra qualquer implementação própria

1. Hook LSM certo pro que você quer bloquear (`bprm_check_security` pra exec, `socket_sendmsg`/`socket_connect`/`socket_create` pra rede — escolha pelo momento exato da decisão, não pelo mais fácil de instrumentar).
2. Retorno `0`/`-EPERM` é a decisão inteira — sem assincronia, sem fila, sem corrida.
3. Resolva dados **das estruturas de kernel que o próprio hook recebe**, nunca releia ponteiro de userspace depois da entrada da syscall.
4. Use `BPF_CORE_READ`/`bpf_core_field_exists` pra qualquer campo de struct que possa ter mudado entre versões de kernel — teste contra mais de uma versão antes de confiar.
5. Map-of-maps (ou equivalente) pra escopar política por unidade de isolamento (container, cgroup, processo), não uma tabela global só.
6. `cilium/ebpf` (Go) é a lib madura de referência pro lado userspace, se a stack for Go.

## Fontes

- [`kubearmor/kubearmor` — enforcer.bpf.c](https://github.com/kubearmor/kubearmor/blob/1f22e362be2de94dc7d8bd22e4c2b821aefa153c/KubeArmor/BPF/enforcer.bpf.c)
- [`kubearmor/kubearmor` — mapHelpers.go](https://github.com/kubearmor/kubearmor/blob/1f22e362be2de94dc7d8bd22e4c2b821aefa153c/KubeArmor/enforcer/bpflsm/mapHelpers.go)
- [KubeArmor — Unraveling BPF LSM Superpowers (blog)](https://kubearmor.io/blog/bpf-lsm-armor)
- [Hardening eBPF for runtime security: Lessons from Datadog Workload Protection](https://www.datadoghq.com/blog/engineering/ebpf-workload-protection-lessons/)
- [LSM BPF Programs — Linux Kernel documentation](https://www.kernel.org/doc/html/v6.3/bpf/prog_lsm.html)
- [Program Type 'BPF_PROG_TYPE_LSM' — eBPF Docs](https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_LSM/)
- [`cilium/ebpf` — Go library for eBPF](https://github.com/cilium/ebpf)
- Exemplo complementar de enforcement mínimo e cirúrgico (um hook só, mitigação de CVE): [`copy-fail-blocker`](https://github.com/cozystack/copy-fail-blocker)
