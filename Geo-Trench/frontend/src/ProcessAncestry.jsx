const labels={
 "explorer.exe":["Windows desktop","The desktop and File Explorer."],
 "cmd.exe":["Command Prompt","Runs text commands and scripts."],
 "powershell.exe":["Windows PowerShell","Runs commands and automation scripts."],
 "pwsh.exe":["PowerShell","Runs commands and automation scripts."],
 "chrome.exe":["Google Chrome","A web browser."],
 "msedge.exe":["Microsoft Edge","A web browser."],
 "firefox.exe":["Firefox","A web browser."],
 "code.exe":["Visual Studio Code","A code editor."],
 "python.exe":["Python","Runs Python programs."],
 "pythonw.exe":["Python","Runs Python programs without a console window."],
 "node.exe":["Node.js","Runs JavaScript programs outside a browser."],
 "winword.exe":["Microsoft Word","A document editor."],
 "excel.exe":["Microsoft Excel","A spreadsheet app."],
 "powerpnt.exe":["Microsoft PowerPoint","A presentation app."],
 "outlook.exe":["Microsoft Outlook","An email and calendar app."],
 "services.exe":["Windows Service Manager","Starts and manages background services."],
 "svchost.exe":["Windows Service Host","Hosts Windows background services."],
 "wininit.exe":["Windows Startup","Starts core Windows services."],
 "winlogon.exe":["Windows Sign-in","Manages parts of the Windows sign-in session."],
 "rundll32.exe":["Windows DLL Runner","Runs functions from Windows library files."],
 "msiexec.exe":["Windows Installer","Installs or removes software packages."]
};
export default function ProcessAncestry({chain=[]}){
 const steps=Array.isArray(chain)?chain.filter(name=>typeof name==="string"&&name.trim()):[];
 const known=name=>labels[name.toLowerCase()];
 return <section className="ancestry-guide" aria-label="How this app started">
  <h4>HOW THIS APP STARTED</h4>
  <p className="ancestry-intro">Programs can start other programs. Read this known chain from top to bottom.</p>
  {steps.length?<ol>{steps.map((name,index)=>{
   const info=known(name),unknown=/^(unknown|unavailable)$/i.test(name);
   return <li key={index}><span className="ancestry-step">{index+1}</span><div><span className="ancestry-relation">{steps.length===1?"Only recorded process":index===0?"Earliest recorded program":index===steps.length-1?"Started this connected app":"Then started"}</span><strong>{unknown?"Program name unavailable":info?.[0]||name}</strong>{info&&<><code>{name}</code><p>{info[1]}</p></>}{!info&&!unknown&&<p>The backend reported this process name; no friendly description is available.</p>}</div></li>;
  })}</ol>:<p className="ancestry-intro">The backend could not retrieve this program's startup history.</p>}
  {!!steps.length&&<p className="ancestry-note">Names come from the backend. Earlier steps may be unavailable; this chain does not tell us who clicked or typed a command.</p>}
 </section>;
}
