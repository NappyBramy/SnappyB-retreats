// ===== SnappyB tool: μόνιμες ημερομηνίες/ώρες στις Υποβολές =====
// Φορτώνεται ΠΡΙΝ το κύριο script του tool. Δεν ξαναγράφει καμία υπάρχουσα συνάρτηση.
// Αποθηκεύει τις αλλαγές σου στο localStorage (κλειδί snb_subdates) και τις εφαρμόζει
// πάνω στα δεδομένα του Sheet κάθε φορά που φορτώνει η λίστα. Δεν χρησιμοποιεί setInterval.
(function(){
  'use strict';
  var KEY='snb_subdates';

  function readDates(){
    try{return JSON.parse(localStorage.getItem(KEY)||'{}')||{};}catch(e){return{};}
  }
  function writeDates(d){
    try{localStorage.setItem(KEY,JSON.stringify(d));}catch(e){}
  }

  // 1) Εφαρμογή των αποθηκευμένων ημερομηνιών στις υποβολές που έρχονται από το Sheet
  var origFetch=window.fetch.bind(window);
  window.fetch=function(url,opts){
    var p=origFetch(url,opts);
    if(typeof url==='string'&&url.indexOf('action=getSubmissions')>-1){
      return p.then(function(res){
        return res.clone().json().then(function(data){
          try{
            var saved=readDates();
            var subs=(data&&data.result&&data.result.submissions)||[];
            subs.forEach(function(s){
              var o=saved[s.row];
              if(!o)return;
              if(o.ci)s.checkin=o.ci;
              if(o.co)s.checkout=o.co;
            });
          }catch(e){}
          return new Response(JSON.stringify(data),{status:res.status,headers:{'Content-Type':'application/json'}});
        }).catch(function(){return res;});
      });
    }
    return p;
  };

  // 2) Αποθήκευση όταν αλλάζεις ημερομηνία ή ώρα σε κάρτα υποβολής
  document.addEventListener('change',function(e){
    var el=e.target;
    if(!el||!el.id)return;
    var m=el.id.match(/^(ci|co|cit|cot)-sub-(\d+)$/);
    if(!m)return;
    var s=window._subs&&window._subs[parseInt(m[2],10)];
    if(!s)return;
    var d=readDates();
    if(!d[s.row])d[s.row]={};
    d[s.row][m[1]]=el.value;
    writeDates(d);
    el.classList.add('changed');
  });

  // 3) Επαναφορά των ωρών (οι ημερομηνίες έρχονται ήδη διορθωμένες από το βήμα 1)
  function applyTimes(){
    var subs=window._subs;
    if(!subs)return;
    var saved=readDates();
    var els=document.querySelectorAll('[id^="cit-sub-"],[id^="cot-sub-"]');
    Array.prototype.forEach.call(els,function(el){
      var m=el.id.match(/^(cit|cot)-sub-(\d+)$/);
      if(!m)return;
      var s=subs[parseInt(m[2],10)];
      if(!s)return;
      var o=saved[s.row];
      if(o&&o[m[1]]&&el.value!==o[m[1]])el.value=o[m[1]];
    });
  }
  function startObserver(){
    var list=document.getElementById('subs-list');
    if(!list)return;
    new MutationObserver(applyTimes).observe(list,{childList:true,subtree:true});
  }
  if(document.getElementById('subs-list'))startObserver();
  else document.addEventListener('DOMContentLoaded',startObserver);
})();
// ===== ΤΕΛΟΣ =====
