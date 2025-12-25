# Análise de IP Suspeito

Ferramenta em Python para análise básica de reputação de endereços IP utilizando heurísticas locais, sem dependência de APIs externas.

## Objetivo
Simular um processo inicial de Threat Intelligence, avaliando se um IP pode ser considerado suspeito com base em seu comportamento e contexto de rede.

## Funcionalidades
- Identificação de IPs públicos e privados
- Verificação de IPs pertencentes a ranges suspeitos
- Detecção de IPs repetidos (possível comportamento de scan)
- Classificação de risco: LOW, MEDIUM ou HIGH
- Explicação clara dos motivos da classificação

## Tecnologias Utilizadas
- Python 3
- Biblioteca ipaddress
- Análise heurística
- Estruturas de dados

## Como Usar
1. Clone o repositório
2. Execute o script com Python
3. Informe um ou mais IPs separados por vírgula
4. Analise o nível de risco e os indicadores apresentados

## Conceitos de Segurança Aplicados
- Threat Intelligence básica
- Reputação de IP
- Indicadores de Comprometimento (IOCs)
- Análise de comportamento em rede

## Observação
Os ranges suspeitos são simulados e utilizados apenas para fins educacionais.
