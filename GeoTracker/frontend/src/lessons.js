// Educational text only. Verdicts and action results always come from the backend.
export const SHELLS=new Set(["cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe"]);
export const ANCESTRY_FLAGS={
 office_spawn:{names:new Set(["winword.exe","excel.exe","powerpnt.exe","outlook.exe"]),note:"The backend flagged an Office app earlier in this startup chain. Documents can launch programs; check whether you expected that."},
 shell_spawn:{names:SHELLS,note:"The backend flagged a command or script host in this chain together with its other checks. Scripts can also be legitimate."}
};
export const RULE_LESSONS={
 suspicious_port:{title:"Connection port",checks:"Checks for ports on the backend's watch list.",why:"Some tools associated with unwanted remote access use these ports.",lookalike:"Development tools and legitimate services can use the same ports.",next:"Check which app opened the connection and whether you intended to use that service."},
 office_spawn:{title:"Started by an Office app",checks:"Looks for Word, Excel, PowerPoint, or Outlook earlier in the startup chain.",why:"A document can start another program through scripts or automation.",lookalike:"Trusted add-ins and document workflows can also start programs.",next:"Check the document and any macros or add-ins before enabling more actions."},
 shell_spawn:{title:"Started by a command or script",checks:"Looks for a shell or script host in the startup chain, alongside the backend's other rules.",why:"Scripts can automate network activity, including activity you did not intend.",lookalike:"Terminals, installers, and developer tools routinely start apps.",next:"Check which task or script started this app and review the other findings."},
 risky_location:{title:"Program location",checks:"Checks whether the executable is in a watched temporary, Downloads, or shared Public folder.",why:"Downloaded or temporary programs can be harder to recognize and trust.",lookalike:"Installers and portable apps often run from these folders.",next:"Check the file's source and publisher before running or moving it."}
};
export const KIND_LABEL={quarantine:"Quarantine an app",restore:"Restore an app",geofence:"Block a region",undo_geofence:"Unblock a region",sync:"Update protection"};
export const STEP_WHY={};

Object.assign(STEP_WHY,{
 "quarantine:verifying target":"Checks that the selected connection still belongs to the same app before taking action.",
 "quarantine:hashing":"A file fingerprint lets the backend recognize this exact file later.",
 "quarantine:stopping process":"Stops the running app before attempting to move its executable.",
 "quarantine:moving to quarantine":"Moves the program into the quarantine location so it can be reviewed.",
 "restore:verifying record":"Checks that this record represents a restorable quarantined file.",
 "restore:checking hash":"Compares the file fingerprint with the saved one to detect changes.",
 "restore:moving back":"Returns the file to its recorded location without launching it.",
 "geofence:applying rule":"Asks Windows Firewall to block the endpoints selected by the backend."
});
