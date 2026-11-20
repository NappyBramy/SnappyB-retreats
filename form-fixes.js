// ===== SnappyB guest form: διορθώσεις (τηλέφωνο, κενό check-in, έτος check-out) =====
// Φορτώνεται ΜΕΤΑ το κύριο script της φόρμας και ξαναορίζει μόνο 3 συναρτήσεις.
var PH_LEN={'30':[10],'90':[10],'359':[9],'40':[9],'49':[10,11],'44':[10],'33':[9],'1':[10],'39':[9,10],'34':[9],'31':[9],'43':[10,11],'41':[9],'48':[9],'420':[9],'380':[9],'381':[8,9],'389':[8],'355':[9],'7':[10]};
function phAllowed(code){return PH_LEN[code]||[7,8,9,10,11];}
function cleanPhone(){
  const raw=g('f-ph').value.trim();
  let code=g('f-ph-code').value.replace(/\D/g,'');
  let d=raw.replace(/\D/g,'');
  if(!d)return null;
  if(/^(\+|00)/.test(raw)){
    d=d.replace(/^00/,'');
    const codes=[...new Set(Array.from(g('f-ph-code').options).map(o=>o.value.replace(/\D/g,'')))].sort((a,b)=>b.length-a.length);
    const m=codes.find(c=>d.startsWith(c));
    if(m){code=m;d=d.slice(m.length);}
  }
  d=d.replace(/^0+/,'');
  const al=phAllowed(code);
  if(!al.includes(d.length)&&d.startsWith(code)&&al.includes(d.length-code.length))d=d.slice(code.length);
  return{code:code,national:d,lens:al,ok:al.includes(d.length)};
}
var PH_MSG={el:'Ο αριθμός κινητού δεν είναι σωστός. Γράψτε μόνο τον αριθμό, χωρίς το πρόθεμα χώρας. Ψηφία που αναμένονται: ',en:'The mobile number is not valid. Enter only the number without the country code. Expected digits: ',tr:'Cep telefonu numarası geçerli değil. Ülke kodu olmadan yalnızca numarayı girin. Beklenen hane sayısı: ',bg:'Nevaliden nomer. Vavedete samo nomera bez koda na darzhavata. Ochakvani tsifri: ',ro:'Numărul de mobil nu este valid. Introduceți doar numărul, fără prefixul țării. Cifre așteptate: '};
function phErr(p){return(PH_MSG[lang]||PH_MSG.en)+(p?p.lens.join(' / '):'');}
function getFullPhone(){
  const raw=g('f-ph').value.trim();
  if(!raw)return'';
  const p=cleanPhone();
  if(!p||!p.ok)return raw;
  return'+'+p.code+' '+p.national;
}
function go(n){
  const T=TX[lang]||TX.el;
  if(curStep===1&&n>1){
    if(!prop){showErr('e1',T.err.prop);return;}
    hideErr('e1');
  }
  if(curStep===2&&n>2){
    const nm=g('f-nm').value.trim(),ct=g('f-ct').value.trim(),zp=g('f-zp').value.trim();
    const isEl=lang==='el',idV=isEl?g('f-el').value.trim():g('f-en').value.trim();
    const ph=g('f-ph').value.trim();
    if(!nm||!ct||!zp||!idV||!ph){showErr('e2',T.err.all);return;}
    const pc=cleanPhone();
    if(!pc||!pc.ok){showErr('e2',phErr(pc));return;}
    g('f-ph').value=pc.national;g('f-ph-code').value='+'+pc.code;phCodeTouched=true;
    hideErr('e2');
  }
  if(curStep===3&&n>3){
    const today=new Date().toISOString().slice(0,10);
    if(!ci||!co){showErr('e3',T.err.all);return;}
    if(ci<today){showErr('e3',T.err.past);['ci-d','ci-m','ci-y'].forEach(id=>g(id).selectedIndex=0);ci='';return;}
    if(co<=ci){showErr('e3',T.err.dates);return;}
    hideErr('e3');buildSum();
  }
  [1,2,3,4].forEach(i=>g('s'+i).classList.toggle('active',i===n));
  g('scnf').classList.remove('show');g('ssuc').classList.remove('show');
  g('cbox').style.display='none';g('subcol').style.display='flex';
  g('prog').style.display='block';
  updProg(n);window.scrollTo({top:0,behavior:'smooth'});
}
function initDates(){
  const now=new Date(),y=now.getFullYear();
  ['ci-d','co-d'].forEach(id=>{
    const s=g(id);s.innerHTML='<option value="">ΗΗ</option>';
    for(let i=1;i<=31;i++)s.innerHTML+='<option value="'+String(i).padStart(2,'0')+'">'+String(i).padStart(2,'0')+'</option>';
  });
  const ciy=g('ci-y');ciy.innerHTML='<option value="">ΕΕΕΕ</option>';
  for(let i=y;i<=y+1;i++)ciy.innerHTML+='<option value="'+i+'">'+i+'</option>';
  const coy=g('co-y');coy.innerHTML='<option value="'+y+'">'+y+'</option><option value="'+(y+1)+'">'+(y+1)+'</option>';
  coy.value=String(y);
  updMonths();
  ['ci-d','ci-m','ci-y'].forEach(id=>g(id).selectedIndex=0);ci='';
  updCiSelects();
}
var _origSetLang=window.setLang;
window.setLang=function(l){_origSetLang(l);const T=TX[l]||TX.el;g('f-ph').placeholder=T.ph.phone.replace(/^\+\d+\s*/,'');};
// Η φόρμα έχει ήδη τρέξει την αρχική της εκκίνηση πριν φορτώσει αυτό το αρχείο, οπότε την ξανατρέχουμε:
initDates();setLang(lang);go(1);
// ===== ΤΕΛΟΣ =====
