import argparse
import re
import math
from collections import Counter
from colorama import Fore, init
from tabulate import tabulate
from typing import List, Dict, Set

# Inicializar Colorama para exibição colorida no terminal
init(autoreset=True)

# Constantes
SPECIAL_CHARACTERS = r'[!@#$%^&*()_+\-=[\]{};\\:"|,.<>\/?]'
LOWERCASE_LETTERS = 26
UPPERCASE_LETTERS = 26
DIGITS = 10
SPECIAL_CHARS = 32

# Banner ASCII para exibir na execução do script
def exibir_banner() -> None:
    banner = """
 ▄▄▄· ▄▄▄· .▄▄ · .▄▄ · • ▌ ▄ ·. ▄▄▄ .▄▄▄▄▄▄▄▄ .▄▄▄  
▐█ ▄█▐█ ▀█ ▐█ ▀. ▐█ ▀. ·██ ▐███•▀▄.▀·•██  ▀▄.▀·▀▄ █·
 ██▀·▄█▀▀█ ▄▀▀▀█▄▄▀▀▀█▄▐█ ▌▐▌▐█·▐▀▀•▄ ▐█.\u00b7▐▀▀•▄▐▀▀▄ 
▐█•·▐█ ▪▐▌▐█▄▪▐█▐█▄▪▐███ ██▌▐█\u2022▐█▄▄▌ ▐█\u2022·▐█▄▄▌▐█•█▌
.▀    ▀  ▀  ▀▀▀▀  ▀▀▀▀ ▀▀  █\u2022▀▀▀ ▀▀▀  ▀▀▀  ▀▀▀ .▀  ▀
"""
    print(Fore.CYAN + banner)

# Função para calcular a entropia de uma senha
def calcular_entropia(senha: str) -> float:
    if not senha:
        return 0.0
    pool = 0
    if re.search(r'[a-z]', senha):
        pool += LOWERCASE_LETTERS
    if re.search(r'[A-Z]', senha):
        pool += UPPERCASE_LETTERS
    if re.search(r'[0-9]', senha):
        pool += DIGITS
    if re.search(SPECIAL_CHARACTERS, senha):
        pool += SPECIAL_CHARS
    return len(senha) * math.log2(pool) if pool > 0 else 0.0

# Função para avaliar a força da senha
def avaliar_forca_senha(senha: str) -> str:
    tamanho = len(senha)
    tipos_caracteres = sum(bool(re.search(pattern, senha)) for pattern in [r'[a-z]', r'[A-Z]', r'[0-9]', SPECIAL_CHARACTERS])

    if tamanho <= 6 or tipos_caracteres == 1:
        return "Muito Fraca"
    elif 7 <= tamanho <= 10 and tipos_caracteres >= 2:
        return "Fraca"
    elif 11 <= tamanho <= 16 and tipos_caracteres >= 2:
        return "Média"
    elif 17 <= tamanho <= 20 and tipos_caracteres >= 3:
        return "Forte"
    elif tamanho >= 21 and tipos_caracteres == 4:
        return "Muito Forte"
    else:
        return "Indeterminada"

# Função para verificar se a senha está na lista "rockyou"
def verificar_rockyou(senha: str, lista_rockyou: Set[str]) -> bool:
    return senha in lista_rockyou

# Função para carregar a lista de senhas populares (rockyou.txt)
def carregar_rockyou(arquivo_rockyou: str) -> Set[str]:
    try:
        with open(arquivo_rockyou, 'r', encoding='latin-1') as file:
            return {linha.strip() for linha in file}
    except FileNotFoundError:
        print(Fore.RED + f"Erro: Arquivo {arquivo_rockyou} não encontrado.")
        return set()

# Função para ler o arquivo de senhas e analisar cada senha
def analisar_senhas(arquivo_senhas: str, lista_rockyou: Set[str]) -> List[Dict[str, str]]:
    try:
        with open(arquivo_senhas, 'r', encoding='latin-1') as file:
            senhas = [linha.strip() for linha in file if linha.strip()]
    except FileNotFoundError:
        print(Fore.RED + f"Erro: Arquivo {arquivo_senhas} não encontrado.")
        return []

    analise = []
    for senha in senhas:
        esta_na_rockyou = verificar_rockyou(senha, lista_rockyou)
        forca = avaliar_forca_senha(senha)
        entropia = calcular_entropia(senha)
        analise.append({'senha': senha, 'forca': forca, 'entropia': entropia, 'rockyou': esta_na_rockyou})

    return analise

# Função para gerar um sumário das senhas analisadas e exibir em tabelas
def gerar_sumario(analise: List[Dict[str, str]]) -> None:
    total_senhas = len(analise)
    senhas_repetidas = [item for item, count in Counter([a['senha'] for a in analise]).items() if count > 1]
    senha_mais_curta = min(analise, key=lambda x: len(x['senha']))
    senha_mais_longa = max(analise, key=lambda x: len(x['senha']))
    entropia_media = sum(a['entropia'] for a in analise) / total_senhas

    # Tabelas de resumo
    tabela_resumo = [
        ["Total de Senhas", total_senhas],
        ["Entropia Média das Senhas", f"{entropia_media:.2f}"]
    ]

    tabela_detalhes = [
        ["Senha Mais Curta", senha_mais_curta['senha'], len(senha_mais_curta['senha'])],
        ["Senha Mais Longa", senha_mais_longa['senha'], len(senha_mais_longa['senha'])],
        ["Senha Menos Forte", min(analise, key=lambda x: x['entropia'])['senha']],
        ["Senha Mais Forte", max(analise, key=lambda x: x['entropia'])['senha']]
    ]

    # Exibir tabelas
    print(Fore.CYAN + "\nResumo da Análise de Senhas:")
    print(tabulate(tabela_resumo, headers=["Descrição", "Valor"], tablefmt="grid", colalign=("center", "center")))
    print(tabulate(tabela_detalhes, headers=["Descrição", "Senha", "Tamanho"], tablefmt="grid", colalign=("center", "center")))

    # Exibir tabela de senhas analisadas
    print(Fore.CYAN + "\nDetalhes das Senhas:")
    tabela_senhas = [[a['senha'], a['forca'], f"{a['entropia']:.2f}", "Sim" if a['rockyou'] else "Não"] for a in analise]
    print(tabulate(tabela_senhas, headers=["Senha", "Força", "Entropia", "Está no RockYou?"], tablefmt="grid", colalign=("center", "center")))

    # Exibir tabela de senhas repetidas
    if senhas_repetidas:
        print(Fore.YELLOW + "\nSenhas Repetidas:")
        tabela_repetidas = [[senha] for senha in senhas_repetidas]
        print(tabulate(tabela_repetidas, headers=[Fore.YELLOW + "Senha"], tablefmt="grid"))
    else:
        print(Fore.GREEN + "\nNenhuma senha repetida encontrada.")

# Função principal para lidar com argumentos e executar o script
def main() -> None:
    parser = argparse.ArgumentParser(
        description='Avaliador de força de senhas baseado em padrões de segurança de 2024.'
    )
    parser.add_argument('arquivo_senhas', help='Arquivo contendo uma senha por linha')
    parser.add_argument('arquivo_senhas_populares', help='Arquivo contendo a lista de senhas populares (rockyou.txt)')
    
    args = parser.parse_args()

    # Exibir Banner
    exibir_banner()

    # Carregar a lista de senhas populares
    lista_rockyou = carregar_rockyou(args.arquivo_senhas_populares)

    # Analisar as senhas do arquivo
    analise = analisar_senhas(args.arquivo_senhas, lista_rockyou)

    # Gerar e imprimir o sumário das análises
    gerar_sumario(analise)

if __name__ == '__main__':
    main()
