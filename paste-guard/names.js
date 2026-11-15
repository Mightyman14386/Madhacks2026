// Supplemental given-name vocabulary, bundled locally. Never sends text away.
const PasteGuardNames = (() => {
  if (!Array.isArray(PG_NAME_DATA) || PG_NAME_DATA.length < 10000) throw new Error("The local name dictionary is missing or incomplete.");
  const names = new Set(PG_NAME_DATA);
  const normalize = value => value.normalize("NFC").toLowerCase().replace(/\u2019/g, "'");
  const boundary = /[\p{L}\p{M}\p{N}_]/u;
  const hasNameContext = prefix => /(?:\b(?:my|his|her|their)\s+name\s+is|\b(?:name|contact|patient|customer|client|employee)\s*:|\b(?:dear|hello|hi|mr|mrs|ms|dr)\.?)\s*$/i.test(prefix);
  function scan(text) {
    const lexicon = nlp.world().model.one.lexicon;
    const found = [], hints = {};
    const urls = [...text.matchAll(/\b(?:https?:\/\/|www\.)\S+/gi)].map(m=>[m.index,m.index+m[0].length]);
    for (const match of text.matchAll(/[\p{L}\p{M}]+(?:['\u2019-][\p{L}\p{M}]+)*/gu)) {
      let value=match[0], key=normalize(value);
      if(!names.has(key) && /['\u2019]s$/i.test(value)){value=value.slice(0,-2);key=normalize(value);}
      if(!names.has(key))continue;
      const start=match.index,end=start+value.length;
      const before=Array.from(text.slice(Math.max(0,start-2),start)).at(-1)||"";
      const after=Array.from(text.slice(end,end+2))[0]||"";
      if(boundary.test(before)||boundary.test(after) || /[@/_]/.test(before+after))continue;
      if(urls.some(([a,b])=>start<b&&a<end))continue;
      const context=hasNameContext(text.slice(Math.max(0,start-100),start));
      const tags=lexicon[key];
      const knownName=tags && (Array.isArray(tags)?tags:[tags]).some(tag=>/^(?:Person|FirstName|LastName|MaleName|FemaleName)$/.test(tag));
      // An existing non-name vocabulary entry needs explicit person context.
      // This keeps May/Will/Rose and ordinary prose from becoming name matches.
      if(tags && !knownName && !context)continue;
      const cased=/\p{Lu}/u.test(value[0]) || value===value.toUpperCase();
      const isolated=text.trim().replace(/[.!?,;:"()\u201c\u201d]/g,"")===value;
      if(!cased&&!context&&!isolated)continue;
      found.push({start,end,value,source:"dictionary",type:"PERSON"});
      if(!tags)hints[value]="FirstName";
    }
    return {found,hints};
  }
  return {scan};
})();
