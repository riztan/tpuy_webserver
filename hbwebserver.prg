/*
openssl genrsa -out privatekey.pem 2048
openssl req -new -subj "/C=LT/CN=mycompany.org/O=My Company" -key privatekey.pem -out certrequest.csr
openssl x509 -req -days 730 -in certrequest.csr -signkey privatekey.pem -out certificate.pem
openssl x509 -in certificate.pem -text -noout
*/

#require "hbssl"
#require "hbhttpd"
#require "hbnetio"

#require "hbcurl"

REQUEST __HBEXTERN__HBSSL__

REQUEST DBFCDX

MEMVAR server, get, post, cookie, session


#include "tpy_netio.ch"

#include "connect.ch"
/* 
 * Ejemplo de contenido para connect.ch
 */
//#define NETSERVER  "localhost"
//#define NETPORT    2941
//#define NETPASSWD  "topsecret"



PROCEDURE Main()

   LOCAL oServer

   LOCAL oLogAccess
   LOCAL oLogError

   LOCAL nPort

   hb_cdpSelect("UTF8")

   IF hb_argCheck( "help" )
      ? "Usage: app [options]"
      ? "Options:"
      ? "  //help               Print help"
      ? "  //stop               Stop running server"
      RETURN
   ENDIF

   IF hb_argCheck( "stop" )
      hb_MemoWrit( ".uhttpd.stop", "" )
      RETURN
   ELSE
      FErase( ".uhttpd.stop" )
   ENDIF

   Set( _SET_DATEFORMAT, "yyyy-mm-dd" )

   oLogAccess := UHttpdLog():New( "hbws_access.log" )

   IF ! oLogAccess:Add( "" )
      oLogAccess:Close()
      ? "Access log file open error " + hb_ntos( FError() )
      RETURN
   ENDIF

   oLogError := UHttpdLog():New( "hbws_error.log" )

   IF ! oLogError:Add( "" )
      oLogError:Close()
      oLogAccess:Close()
      ? "Error log file open error " + hb_ntos( FError() )
      RETURN
   ENDIF

   ? "Listening on port:", nPort := 8002

   ? "CONNECTING... TPuy Server "
   ? "netio_Connect():", netio_Connect( NETSERVER, NETPORT,, NETPASSWD )
   ?
   ?

   oServer := UHttpdNew()

   IF ! oServer:Run( { ;
         "FirewallFilter"      => "", ;
         "LogAccess"           => {| m | oLogAccess:Add( m + hb_eol() ) }, ;
         "LogError"            => {| m | oLogError:Add( m + hb_eol() ) }, ;
         "Trace"               => {| ... | QOut( ... ) }, ;
         "Port"                => nPort, ;
         "Idle"                => {| o | iif( hb_FileExists( ".uhttpd.stop" ), ( FErase( ".uhttpd.stop" ), o:Stop() ), NIL ) }, ;
         "PrivateKeyFilename"  => "privatekey.pem", ;
         "CertificateFilename" => "certificate.pem", ; //"certificate.crt", ;
         "SSL"                 => .T., ;
         "Mount"               => { ;
         "/rne_votante"        => @proc_tpuy(), ;
         "/uctoutf8"           => @proc_uctoutf8(), ;
         "/hello"              => {|| UWrite( "Hello!" ) }, ;
         "/info"               => {|| UProcInfo() }, ;
         "/"                   => {|| URedirect( "/hello" ) } } } )
      oLogError:Close()
      oLogAccess:Close()
      ? "Server error:", oServer:cError
      ErrorLevel( 1 )
      RETURN
   ENDIF

   oLogError:Close()
   oLogAccess:Close()

   RETURN



STATIC FUNCTION FromRemote( cFuncName, cObj, ... )
   local uReturn

   if hb_pValue(1) = nil ; return nil ; endif
//tracelog( "solicitando "+cFuncName+" , , ..." )
? procname()
? "EJECUTANDO ", cFuncName
   uReturn := hb_deserialize( netio_funcexec( cFuncName, "", cObj, ...  ) )
return uReturn //hb_deserialize( netio_funcexec( ... ) )


STATIC FUNCTION proc_uctoutf8()
   local cCode, hResult, cResult
   local cResp := "json"
   local aResp := {"json","hb"}

   IF hb_HHasKey( get, "code" )
      cCode := PadR( get["code"], 1 )
      if Empty(cCode) ; RETURN NIL ; endif
   ENDIF

   IF hb_HHasKey( get, "res" )
      if ASCAN( aResp, {|a| a=get["res"] } ) > 0  
         cResp := get["res"]
      endif
   ENDIF

   cResult := net:uctoutf8( cCode )
   if Empty( cResult )
      RETURN NIL
   endif

   hResult := { "utf8"=>cResult, "string" => hb_hextostr(cResult) }

   Do Case 
      Case cResp = "json"
         UWrite( hb_jsonEncode( hResult ) ) 
      Case cResp = "hb"
         UWrite( hb_ValToExp( cResult ) )
   EndCase

   RETURN NIL




STATIC FUNCTION proc_tpuy()
   local cNac, cCedula, aResult, hResult
   local cResp := "json"
   local aResp := {"json","hb"}
   
   IF hb_HHasKey( get, "nac" )
      cNac := PadR( get["nac"], 1 )
      if Empty(cNac) ; RETURN NIL ; endif
   ENDIF
   IF hb_HHasKey( get, "cedula" )
      cCedula := PadR( get["cedula"], 12 )
      if Empty(cCedula) ; RETURN NIL ; endif
   ENDIF

   IF hb_HHasKey( get, "res" )
      if ASCAN( aResp, {|a| a=get["res"] } ) > 0  
         cResp := get["res"]
      endif
   ENDIF


? "invocando al netio.."
   aResult := ~RNE_GetVotante( cNac, cCedula )[1]
? hb_ValToExp(aResult)
   if Empty( aResult )
      RETURN NIL
   endif
   hResult := { "primer_nombre"=>aResult[1], "segundo_nombre" => aResult[2], ;
                "primer_apellido"=>aResult[3], "segundo_apellido"=> aResult[4] }
   Do Case 
      Case cResp = "json"
         UWrite( hb_jsonEncode( hResult ) ) 
      Case cResp = "hb"
         UWrite( hb_ValToExp( aResult ) )
   EndCase


   RETURN NIL


//eo
