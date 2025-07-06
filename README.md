# Nome do projeto:
Scanner de Portas usando Nmap e Wireshark

# Descrição do Projeto:
Um scanner de portas é uma ferramenta que "bate" em cada uma dessas portas para ver qual é a sua condição:
ABERTA (OPEN): Há um serviço ativo ouvindo e pronto para aceitar uma conexão. A porta está destrancada.
FECHADA (CLOSED): O computador responde ativamente que não há serviço naquela porta, a porta está trancada, e há um aviso dizendo isso.
FILTRADA (FILTERED): Não há resposta. Um firewall ou outro dispositivo de segurança está bloqueando o acesso, então não conseguimos saber se a porta está aberta ou fechada.

# Como Instalar:
A instalação envolve 4 passos principais:
garantir que o Python está instalado
instalar o scan Nmap, instalar o analisador Wireshark
preparar e executar o script.

Passo a passo, com instruções para Windows e Linux.
1- Instalar o Python: A linguagem de programação que executa o script.
2- Instalar o Nmap: A ferramenta essencial que realiza o escaneamento de rede.
3- Instalar o Wireshark: A ferramenta para visualizar o tráfego de rede gerado pelo scan.
4- Baixar o Script e Instalar Dependências: Preparar o ambiente final para rodar o script.

Passo 1: Instalar o Python
É muito provável que você já tenha o Python. Para verificar, abra o terminal (Prompt de Comando ou PowerShell no Windows) e digite:
python --version
Se ele mostrar uma versão (ex: Python 3.13.3),
você tem o Python instalado.
Se der um erro, siga as instruções abaixo.

No Windows:
Vá para o site oficial do Python: https://www.python.org/downloads/
Baixe o instalador mais recente.
Execute o instalador.
ATENÇÃO: Na primeira tela do instalador, marque a caixa que diz "Add Python to PATH" ou "Adicionar Python ao PATH".
Isso é extremamente importante para que o sistema reconheça os comandos do Python.
Prossiga com a instalação padrão.

No Linux (Debian/Ubuntu):
O Python geralmente já vem instalado. Caso não venha, é muito simples de instalar via terminal:
sudo apt update
sudo apt install python3 python3-pip

Passo 2: Instalar o Nmap
O script depende do Nmap para a funcionalidade de scan avançado.

No Windows:
Vá para a página de download do Nmap: https://nmap.org/download.html
Procure pela seção "Microsoft Windows binaries" e baixe o instalador .exe mais recente (ex: nmap-7.95-setup.exe).
Execute o instalador e siga as instruções.
Não precisa alterar nenhuma opção, a instalação padrão é suficiente e já adicionará o Nmap ao PATH do sistema automaticamente.

No Linux (Debian/Ubuntu):
Instale diretamente pelo terminal com um único comando:
sudo apt update
sudo apt install nmap
Verificação: Após a instalação, abra um novo terminal e digite nmap --version.
Se ele mostrar informações sobre a versão do Nmap, a instalação foi um sucesso!

Passo 3: Instalar o Wireshark:
Este passo é opcional, necessário apenas se você quiser usar a funcionalidade de capturar e visualizar o tráfego do scan.

No Windows:
Vá para a página de download do Wireshark: https://www.wireshark.org/download.html
Baixe o instalador para Windows (64-bit).
Execute o instalador, durante o processo, ele perguntará se deseja instalar o Npcap, diga que sim, pois este é o componente que efetivamente captura os pacotes de rede.
Prossiga com as opções padrão.

No Linux (Debian/Ubuntu):
Instale pelo terminal:
sudo apt update
sudo apt install wireshark
Durante a instalação, uma tela azul aparecerá perguntando: "Deverão os não-superusuários ser capazes de capturar pacotes?".
É seguro e recomendado selecionar <Sim> ou <Yes> para que você não precise usar sudo toda vez que for abrir o Wireshark.

Passo 4: Preparar e Executar o Script
Agora que todas as ferramentas estão instaladas, vamos preparar e rodar nossa aplicação.

Salve o Código: Copie o código Python do scanner e salve-o em um arquivo em seu computador.
Instale a Biblioteca Python para o Nmap: O script precisa de uma "ponte" para se comunicar com o Nmap.
Essa ponte é a biblioteca python-nmap.

Abra seu terminal (Prompt de Comando, PowerShell, etc.).
Digite o seguinte comando e pressione Enter:
pip install python-nmap
Execute a Aplicação:
Navegue pelo terminal até a pasta onde você salvou o script.

Lembre-se: para usar o scan do Nmap, o script precisa de privilégios de administrador.
Executando no Windows:
a. Procure por "Prompt de Comando" ou "PowerShell" no Menu Iniciar.
b. Clique com o botão direito sobre ele e selecione "Executar como administrador".
c. Na janela do terminal de administrador que abrir, navegue até a pasta do script através do Python ou VSCODE.
d. Execute o script

Executando no Linux:
a. Abra o terminal.
b. Navegue até a pasta do script.
c. Execute o script usando sudo

A interface gráfica do Scanner de Portas Avançado deverá abrir, e agora você está pronto para usar.
O script cria e salva os logs em uma pasta para posteriormente fazer uma analise mais detalhatada e minunciosa.

# Funcionalidade:
o Nmap é a ferramenta de ação que sonda ativamente a rede, enquanto o Wireshark é a ferramenta de observação que fornece um registro detalhado e uma análise profunda dessa ação e de suas consequências.

# Tecnologias usadas:
Linguagem Python, Nmap e Wireshark
