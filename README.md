<div align="center">
  <h1>
    <img src="./assets/logo.svg" width="40" height="40" alt="Security Scanner Logo" style="vertical-align: middle; margin-right: 10px;">
    Espeon
  </h1>

  <p>Um scanner de vulnerabilidades avançado baseado em Nmap com geração de relatórios inteligente e verificação de CVEs.</p>
</div>

## 🚀 Recursos

- 🔍 Escaneamento completo de portas com detecção de serviços
- 🛡️ Detecção de firewall
- 🌐 Suporte a escaneamento UDP
- 📊 Múltiplos formatos de relatório (JSON, CSV, TXT)
- 🔍 Detecção de Sistema Operacional
- 🔒 Verificação automática de CVEs via NVD API
- ⚙️ Configurações personalizáveis via arquivo config.json

## 📋 Pré-requisitos

- Python 3.6+
- Nmap instalado no sistema
- Chave de API do NVD (National Vulnerability Database)

## 🛠️ Instalação

1. Clone o repositório:
```bash
git clone https://github.com/seu-usuario/espeon.git
cd espeon
```
2. Crie e ative o ambiente virtual:
```bash
python -m venv nome_do_ambiente
```
* Ativação do ambiente virtual:

macOs/Linux
```bash
source nome_do_ambiente/bin/activate
```
  Windows:
```bash
.\nome_do_ambiente\Scripts\activate
```
3. Instale as dependências:
```bash
pip install -r requirements.txt
```
4. Configure o ambiente:
```bash
cp config.example.json config.json
cp .env.example .env
```
5. Adicione sua chave API do NVD ao arquivo .env:
```bash
NVD_API_KEY=sua-chave-aqui
```
## 💻 Uso

Exemplo básico de uso:
```bash
python main.py --host exemplo.com
```
Opções disponíveis:
```bash
python main.py --help
```
### Argumentos
* --host: Host alvo para escaneamento (obrigatório)
* --ports: Range de portas para escanear (padrão: 1-65535)
* --os-detection: Ativa detecção de sistema operacional
* --udp: Ativa escaneamento UDP
* --firewall: Ativa detecção de firewall
* --script: Especifica script personalizado do Nmap
* --output: Formato de saída (json, txt, csv)

## ⚙️ Configuração
O arquivo config.json permite personalizar configurações padrão:

```json
{
  "default_ports": "1-65535",
  "enable_udp_scan": false,
  "enable_firewall_detection": false,
  "custom_nmap_scripts": ""
}
```
## 📄 Formatos de Relatório

### TXT

* Relatório detalhado legível por humanos
* Inclui análise de segurança e CVEs encontrados
* Recomendações de mitigação
### CSV

* Formato tabulado para análise em planilhas
* Ideal para processamento de dados
* Lista detalhada de portas e vulnerabilidades

### JSON

* Formato estruturado para integração com outras ferramentas
* Contém todos os dados brutos do scan
* Inclui metadados completos

## 🤝 Contribuindo

Contribuições são bem-vindas! Sinta-se à vontade para:

1. Fazer fork do projeto
2. Criar uma branch para sua feature (git checkout -b feature/AmazingFeature)
3. Commit suas mudanças (git commit -m 'Add some AmazingFeature')
4. Push para a branch (git push origin feature/AmazingFeature)
5. Abrir um Pull Request

## ⚠️ Aviso Legal

Este scanner deve ser usado apenas em redes e sistemas que você tem permissão para testar. O uso indevido desta ferramenta pode ser ilegal.

<!--
## 📝 Licença

Este projeto está licenciado sob a MIT License - veja o arquivo LICENSE para detalhes.-->

<!--
Distribuição
    Distribuição:
        Empacotar o projeto como uma ferramenta instalável com setuptools.
        Publicar no PyPI para facilitar a instalação:

        pip install espeon

Monitoramento em Tempo Real
    Adicionar uma opção para executar varreduras periódicas e monitorar hosts constantemente.
    Armazenar os resultados em um banco de dados SQLite ou MongoDB.

Futuro: Tornar-se uma Ferramenta Completa
    Interface Web:
        FastAPI para criar uma interface web interativa.
        Exibir os resultados do scan e relatórios em tempo real no navegador.

    Módulos de Expansão:
        Suporte a outros scanners, como OpenVAS ou Nikto, para complementar o Nmap.

-->