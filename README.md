# !!Deprecated!!

This library was only ever intented to fill a temporary gap in functionality that existed in ASP.NET MVC, but had not quite made it to ASP.NET Core. That has now been addressed. As such I will no longer be maintaining this code base. Please consider using the official WsFed library here:

https://www.nuget.org/packages/Microsoft.AspNetCore.Authentication.WsFederation

# WsFederation for ASP.NET Core

This is a port of the Katana WsFederation middleware for ASP.NET Core. This project has a hard dependency on the full .NET Framework as many of the required BCL classes do not exist in the .NET Standard.

# Installation

```
PM> Install-Package AspNetCore.Authentication.WsFederation
```
