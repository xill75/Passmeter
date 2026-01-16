import argparse
import csv
import textwrap
from tabulate import tabulate
from collections import Counter
from colorama import Fore, Style, init
from zxcvbn import zxcvbn

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

def analisar_senha_zxcvbn(senha, user_inputs=[]):
    """
    Analisa a senha usando zxcvbn e retorna score, tempo e feedback.
    """
    resultado = zxcvbn(senha, user_inputs=user_inputs)
    
    # Tratamento correto do feedback
    warning = resultado['feedback']['warning']
    suggestions = resultado['feedback']['suggestions']
    
    feedback_lista = [warning] if warning else []
    feedback_lista.extend(suggestions)
    
    return {
        'score': resultado['score'], # 0 a 4
        'crack_time': resultado['crack_times_display']['offline_slow_hashing_1e4_per_second'],
        'feedback': ", ".join(feedback_lista)
    }

def carregar_rockyou(arquivo_rockyou):
    if not arquivo_rockyou:
        return set()
    try:
        with open(arquivo_rockyou, 'r', encoding='utf-8', errors='ignore') as file:
            return {linha.strip() for linha in file}
    except FileNotFoundError:
        print(Fore.RED + f"[!] Arquivo '{arquivo_rockyou}' não encontrado. Continuando sem wordlist.")
        return set()

def verificar_rockyou(senha, lista_rockyou):
    return senha in lista_rockyou

def analisar_senhas(arquivo_senhas, lista_rockyou):
    analise = []
    try:
        with open(arquivo_senhas, 'r', encoding='utf-8', errors='ignore') as file:
            for linha in file:
                senha = linha.strip()
                if senha:
                    dados_zxcvbn = analisar_senha_zxcvbn(senha)
                    esta_na_rockyou = verificar_rockyou(senha, lista_rockyou)
                    
                    analise.append({
                        'senha': senha,
                        'forca': dados_zxcvbn['score'],
                        'tempo': dados_zxcvbn['crack_time'],
                        'feedback': dados_zxcvbn['feedback'],
                        'rockyou': esta_na_rockyou
                    })
    except FileNotFoundError:
        print(Fore.RED + f"[!] Arquivo de senhas '{arquivo_senhas}' não encontrado.")
        return []
    return analise

def gerar_sumario(analise, mostrar_senhas=False):
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

    print(Fore.CYAN + "\nResumo das Senhas:")
    print(tabulate(tabela_resumo, headers=["Descrição", "Valor"], tablefmt="grid"))

    print(Fore.CYAN + "\nEstatísticas:")
    print(tabulate(tabela_detalhes, headers=["Descrição", "Senha/Valor", "Comp/Info"], tablefmt="grid"))

    tabela_senhas = []
    for a in analise:
        # Corrige o layout quebrando o texto em linhas de 40 caracteres
        feedback_formatado = textwrap.fill(a['feedback'], width=40)
        
        tabela_senhas.append([
            mask(a['senha']), 
            a['forca'], 
            a['tempo'], 
            "Sim" if a['rockyou'] else "Não",
            feedback_formatado
        ])
    
    print(Fore.CYAN + "\nAnálise Detalhada:")
    print(tabulate(tabela_senhas, headers=["Senha", "Score", "Tempo Quebra", "RockYou", "Feedback"], tablefmt="grid"))

    if senhas_repetidas:
        print(Fore.YELLOW + f"\n[!] Encontradas {len(senhas_repetidas)} senhas repetidas.")

def main():
    parser = argparse.ArgumentParser(description="Analisador de Senhas (zxcvbn + wordlist)")
    parser.add_argument("arquivo_senhas", help="Arquivo contendo as senhas a serem analisadas")
    parser.add_argument("--rockyou", help="Caminho para wordlist (opcional)", default=None)
    parser.add_argument("--show", action="store_true", help="Exibe as senhas em texto claro (Cuidado!)")
    parser.add_argument("--csv", help="Salvar relatório em CSV", metavar="FILE")
    
    args = parser.parse_args()

    lista_rockyou = carregar_rockyou(args.rockyou)

    print(Fore.YELLOW + "[*] Analisando senhas...")
    analise = analisar_senhas(args.arquivo_senhas, lista_rockyou)

    gerar_sumario(analise, mostrar_senhas=args.show)

    if args.csv and analise:
        try:
            with open(args.csv, 'w', newline='', encoding='utf-8') as f:
                campos = ['senha', 'forca', 'tempo', 'feedback', 'rockyou']
                writer = csv.DictWriter(f, fieldnames=campos)
                writer.writeheader()
                writer.writerows(analise)
            print(Fore.GREEN + f"\n[+] Relatório CSV salvo em: {args.csv}")
        except Exception as e:
            print(Fore.RED + f"\n[!] Erro ao salvar CSV: {e}")

if __name__ == "__main__":
    exibir_banner()
    main()