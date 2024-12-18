# Passmeter

# Avaliador de Força de Senhas (PassMeter)

Este projeto é um avaliador de força de senhas baseado em padrões de segurança de 2024. Ele analisa um arquivo de senhas, verifica a presença das senhas em uma lista de senhas populares (como o arquivo `rockyou.txt`) e avalia a força e a entropia de cada senha.

## Funcionalidades

- **Análise de Senhas**: Avalia cada senha com base em critérios de força, como comprimento e diversidade de caracteres (minúsculas, maiúsculas, números, caracteres especiais).
- **Verificação no RockYou**: Verifica se a senha está presente na lista de senhas populares.
- **Cálculo de Entropia**: Calcula a entropia da senha para avaliar seu nível de complexidade.
- **Exibição de Relatórios**: Exibe as senhas analisadas em uma tabela, incluindo a força, entropia e se a senha está no arquivo `rockyou.txt`. Também fornece um resumo geral das senhas.

## Exemplo de uso 

python passmeter.py senhas.txt rockyou.txt

### Requisitos

Antes de rodar o script, instale as dependências do projeto com o seguinte comando:

```bash
pip install -r requirements.txt

