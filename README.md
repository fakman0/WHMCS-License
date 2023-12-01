# BYPASS AND NULLED WHMCS LICENSE.PHP

Me complace compartir el resultado de mi reciente proyecto de actualización completa del archivo License.php para WHMCS. Aunque fue un desafío, disfruté cada momento dedicado a investigar y simplificar la solución. A lo largo de los años, he contribuido significativamente a esta comunidad, y a pesar de mis intentos de informar sobre este problema a WHMCS, la respuesta no fue positiva. Por esta razón, decidí compartir esta solución con aquellos que deseen utilizar este increíble software para sus proyectos.

![Force Check](https://github.com/jesussuarz/whmcs-nulled-license-full-update/blob/main/img/force_license.png?raw=true)

¿Cómo funciona? Simplemente reemplace el archivo License.php en la ubicación de su instalación de WHMCS, ya sea antes o después de instalar el software. La ruta es:

```
/vendor/whmcs/whmcs-foundation/lib/License.php
```
**Este archivo de licencias está diseñado para versiones superiores a v8.7.x.**

Siéntase libre de ingresar cualquier número de licencia tanto en la instalación inicial como después de instalarlo en el archivo configuration.php. Todo se verifica con el archivo License.php.

Reitero, con esta solución, puede tener WHMCS COMPLETO con todas las actualizaciones oficiales de WHMCS. (Puede revisar el código; mi enfoque fue mantener casi todas las validaciones originales y ajustar solo lo necesario para que el software crea que tiene una licencia válida. Sin embargo, todas las validaciones se realizan con los servidores de WHMCS:

```
    const LICENSE_API_HOSTS = ["a.licensing.whmcs.com", "b.licensing.whmcs.com", "c.licensing.whmcs.com", "d.licensing.whmcs.com", "e.licensing.whmcs.com", "f.licensing.whmcs.com"];
    const STAGING_LICENSE_API_HOSTS = ["hou-1.licensing.web.staging.whmcs.com"];
```

![Check Update](https://github.com/jesussuarz/whmcs-nulled-license-full-update/blob/main/img/update_check.png?raw=true)

Si tiene alguna pregunta o inquietud, no dude en abrir un problema en: https://github.com/jesussuarz/whmcs-nulled-license-full-update/issues (resolveré cualquier problema tan pronto como sea posible). También puede plantear el problema en inglés.

Tenga en cuenta que puede obtener versiones oficiales tan solo en el siguiente enlace: https://s3.amazonaws.com/releases.whmcs.com/v2/pkgs/whmcs-8.8.0-release.1.zip (solo cambia la version del release y obtendras versiones sin ninguna modificacion)

Por último, quiero expresar mi agradecimiento especial al equipo de https://easytoyou.eu/ y, en particular, a "Miguel" por ofrecer sus servicios para descifrar la última versión del archivo de licencias de WHMCS, lo que hizo posible este proyecto.

Para obtener más detalles sobre este proyecto, puede visitar mi publicación en LinkedIn: https://www.linkedin.com/posts/jesussuarz_github-jesussuarzwhmcs-nulled-license-full-update-activity-7132283748267503616-N8wx

