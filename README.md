# WHMCS LICENSE FULL UPDATE
La verdad me divertí bastante haciendo esto, aunque fue bastante desafiante el trabajo de lograrlo, invertí muchas horas de investigación para simplificar la solución, mi objetivo era solo ver si era posible lograr tener actualizaciones de WHMCS gratis, (aunque ya no uso WHMCS para mis proyectos), desde hace años he aportado mucho conocimiento a esta comunidad, intente reportar este problema sin embargo WHMCS no esta interesada en resolverlo, por eso decidí publicar esto para quienes deseen usar este maravilloso software para sus proyectos. 

![Force Check](https://github.com/jesussuarz/whmcs-nulled-license-full-update/blob/main/force_license.png?raw=true)

¿Entonces cómo funciona? Simplemente reemplace el archivo de License.php en la ubicación de su whmcs antes o después de instalar el software. La ruta es: 
```
/vendor/whmcs/whmcs-foundation/lib/License.php
```
Siéntete en libertad de colocar cualquier número licencia tanto en la instalación inicial, como después de instalarlo en el archivo de configuration.php, ya que todo se verifica con el archivo de License.php

**Reitero, con esta solución usted puede tener WHMCS FULL, y con todas actualizaciones oficiales de WHMCS. (puedes revisar el código, mi idea fue dejar el código con casi todas las validaciones originales y solo ajustar lo necesario para que el software pudiese pensar que tenia una licencia valida, pero todo se valida con los servidores de WHMCS:**
```
    const LICENSE_API_HOSTS = ["a.licensing.whmcs.com", "b.licensing.whmcs.com", "c.licensing.whmcs.com", "d.licensing.whmcs.com", "e.licensing.whmcs.com", "f.licensing.whmcs.com"];
    const STAGING_LICENSE_API_HOSTS = ["hou-1.licensing.web.staging.whmcs.com"];
```

![Check Update](https://github.com/jesussuarz/whmcs-nulled-license-full-update/blob/main/update_check.png?raw=true)

Si tienes dudas, puedes abrir un problema en: [https://github.com/jesussuarz/whmcs-nulled-license-full-update/issues](https://github.com/jesussuarz/whmcs-nulled-license-full-update/issues) (lo resolveré tan pronto sea posible). You can write the problem in English.

Quiero dar gracias especiales al equipo de https://easytoyou.eu/ y muy en especial a “miguel” que estuvo dispuesto a ofrecer sus servicios para descifrar la última versión del archivo de Licencias de WHMCS para lograr esto.
