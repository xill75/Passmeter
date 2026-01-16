import argparse
import re
from collections import Counter
from colorama import Fore, Style, init
from tabulate import tabulate
import math

# Inicializar Colorama
init(autoreset=True)

def exibir_banner():
    banner = r"""
 ▄▄▄· ▄▄▄· .▄▄ · .▄▄ · • ▌ ▄ ·. ▄▄▄ .▄▄▄▄▄▄▄▄ .▄▄▄  
▐█ ▄█▐█ ▀█ ▐█ ▀. ▐█ ▀. ·██ ▐███•▀▄.▀·•██  ▀▄.▀·▀▄ █·
 ██▀·▄█▀▀█ ▄▀▀▀█▄▄▀▀▀█▄▐█ ▌▐▌▐█·▐▀▀•▄ ▐█.·▐▀▀•▄▐▀▀▄ 
▐█•·▐█ ▪▐▌▐█▄▪▐█▐█▄▪▐███ ██▌▐█•▐█▄▄▌ ▐█•·▐█▄▄▌▐█•█▌
.▀   ▀  ▀  ▀▀▀▀  ▀▀▀▀ ▀▀  █•▀▀▀ ▀▀▀  ▀▀▀  ▀▀▀ .▀  ▀
"""
    print(Fore.CYAN + banner)

# Função para calcular a entropia de uma senha
def calcular_entropia(senha):
    """
    Calcula a entropia da senha para avaliar sua complexidade.
    A entropia é baseada no comprimento e na diversidade de caracteres da senha.
    """
    if len(senha) == 0:
        return 0
    pool = 0
    if re.search(r'[a-z]', senha):
        pool += 26  # Letras minúsculas
    if re.search(r'[A-Z]', senha):
        pool += 26  # Letras maiúsculas
    if re.search(r'[0-9]', senha):
        pool += 10  # Dígitos numéricos
    if re.search(r'[!@#$%^&*()_+\-=[\]{};\\:\"|,.<>\/?]', senha):
        pool += 32  # Caracteres especiais
    return len(senha) * math.log2(pool) if pool > 0 else 0

# Função para avaliar a força da senha
def avaliar_forca_senha(senha):
    """
    Avalia a força da senha com base no tamanho e na diversidade de caracteres.
    """
    tamanho = len(senha)
    tipos_caracteres = 0

    # Verifica a presença de diferentes tipos de caracteres
    if re.search(r'[a-z]', senha):
        tipos_caracteres += 1
    if re.search(r'[A-Z]', senha):
        tipos_caracteres += 1
    if re.search(r'[0-9]', senha):
        tipos_caracteres += 1
    if re.search(r'[!@#$%^&*()_+\-=[\]{};\\:\"|,.<>\/?]', senha):
        tipos_caracteres += 1

    # Avalia a senha com base em seu comprimento e diversidade de caracteres
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
def verificar_rockyou(senha, lista_rockyou):
    return senha in lista_rockyou

# Função para carregar a lista de senhas populares (rockyou.txt)
def carregar_rockyou(arquivo_rockyou):
    """
    Carrega as senhas do arquivo rockyou.txt para uma lista.
    """
    with open(arquivo_rockyou, 'r', encoding='latin-1') as file:
        return {linha.strip() for linha in file}

# Função para ler o arquivo de senhas e analisar cada senha
def analisar_senhas(arquivo_senhas, lista_rockyou):
    """
    Lê o arquivo de senhas e avalia cada senha.
    Para cada senha, calcula sua força, entropia e verifica se está na lista de senhas populares.
    """
    senhas = []
    with open(arquivo_senhas, 'r', encoding='latin-1') as file:
        for linha in file:
            senha = linha.strip()
            if senha:  # Verifica se a linha não está vazia
                senhas.append(senha)

    analise = []
    for senha in senhas:
        esta_na_rockyou = verificar_rockyou(senha, lista_rockyou)
        forca = avaliar_forca_senha(senha)
        entropia = calcular_entropia(senha)
        analise.append({'senha': senha, 'forca': forca, 'entropia': entropia, 'rockyou': esta_na_rockyou})

    return analise

# Função para gerar um sumário das senhas analisadas e exibir em tabelas
def gerar_sumario(analise):
    """
    Gera um sumário das senhas analisadas, incluindo detalhes como senhas mais curtas,
    mais longas, mais fortes, e senhas repetidas.
    """
    total_senhas = len(analise)
    if total_senhas == 0:
        return

    senhas_repetidas = [item for item, count in Counter([a['senha'] for a in analise]).items() if count > 1]
    
    senha_mais_curta = min(analise, key=lambda x: len(x['senha']))
    senha_mais_longa = max(analise, key=lambda x: len(x['senha']))
    score_medio = sum(a['forca'] for a in analise) / total_senhas

    def mask(s): return s if mostrar_senhas else "*" * len(s)

    tabela_resumo = [
        ["Total de Senhas", total_senhas],
        ["Score Médio (0-4)", f"{score_medio:.2f}"]
    ]

    tabela_detalhes = [
        ["Senha Mais Curta", mask(senha_mais_curta['senha']), len(senha_mais_curta['senha'])],
        ["Senha Mais Longa", mask(senha_mais_longa['senha']), len(senha_mais_longa['senha'])],
        ["Menor Score", min(analise, key=lambda x: x['forca'])['forca'], "-"],
        ["Maior Score", max(analise, key=lambda x: x['forca'])['forca'], "-"]
    ]

    # Exibir tabelas
    print(Fore.CYAN + "\nResumo da Análise de Senhas:")
    print(tabulate(tabela_resumo, headers=["Descrição", "Valor"], tablefmt="grid", colalign=("center", "center")))
    print(tabulate(tabela_detalhes, headers=["Descrição", "Senha", "Tamanho"], tablefmt="grid", colalign=("center", "center")))

    # Exibir tabela de senhas analisadas
    print(Fore.CYAN + "\nDetalhes das Senhas:")
    tabela_senhas = [[a['senha'], a['forca'], f"{a['entropia']:.2f}", "Sim" if a['rockyou'] else "Não"] for a in analise]
    print(tabulate(tabela_senhas, headers=["Senha", "Força", "Entropia", "Está no RockYou?"], tablefmt="grid", colalign=("center", "center")))

    if senhas_repetidas:
        print(Fore.YELLOW + "\nSenhas Repetidas:")
        tabela_repetidas = [[senha] for senha in senhas_repetidas]
        print(tabulate(tabela_repetidas, headers=[Fore.YELLOW + "Senha"], tablefmt="grid"))
    else:
        print(Fore.GREEN + "\nNenhuma senha repetida encontrada.")

# Função principal para lidar com argumentos e executar o script
def main():
    """
    Função principal que lida com os argumentos passados ao script e executa as análises
    de senhas e gera os relatórios.
    """
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

if __name__ == "__main__":
    exibir_banner()
    main()