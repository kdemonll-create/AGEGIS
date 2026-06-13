/* ============================================================================
   AEGIS — shared client runtime
   ----------------------------------------------------------------------------
   ONE codebase, TWO deployment modes — auto-detected at boot:

     • LOCAL  (standalone) — no server. Open the .html files directly.
                             Data + credentials live in this browser only.
                             The login is a CONVENIENCE LOCK, not a real
                             security boundary (anyone with file access can
                             read localStorage). Use the secure mode for that.

     • SECURE (server)     — the Node/Express server is serving these files.
                             Real session auth (httpOnly cookie, scrypt-hashed
                             passwords) + a real database (SQLite by default).

   Detection: probe GET /api/status. Reachable → SECURE, else → LOCAL.
   ============================================================================ */
(function (global) {
  'use strict';

  var COLLECTIONS = ['threats','personnel','regions','osint','tasks','trips','itinerary','hotels','budget','iw_entries','iw_entities','iw_rels','iw_ach'];
  var LS = {
    cred:   'aegis.cred',
    cfg:    'aegis.config',
    coll:   function (c) { return 'aegis.coll.' + c; },
    session:'aegis.session'
  };

  var AEGIS = {
    MODE: 'local',
    version: 1,
    _user: null,
    _configured: false,
    _config: null,
    _apiBuild: function(p){ return '/api'+p; },  // set during boot; falls back to query-string routing on hosts without URL rewriting
    ready: null
  };

  /* ---------------- tiny helpers ---------------- */
  function esc(s){ return (s==null?'':String(s)).replace(/[&<>"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];}); }
  function uid(p){ return (p||'') + Date.now().toString(36) + Math.random().toString(36).slice(2,6); }
  function hex(buf){ return [].map.call(new Uint8Array(buf),function(b){return b.toString(16).padStart(2,'0');}).join(''); }
  function dtgNow(){
    var d=new Date(), p=function(n){return String(n).padStart(2,'0');};
    var M=['JAN','FEB','MAR','APR','MAY','JUN','JUL','AUG','SEP','OCT','NOV','DEC'];
    return p(d.getUTCDate())+p(d.getUTCHours())+p(d.getUTCMinutes())+'Z '+M[d.getUTCMonth()]+' '+String(d.getUTCFullYear()).slice(2);
  }
  function flash(msg){
    var f=document.getElementById('flash');
    if(!f){ f=document.createElement('div'); f.id='flash'; f.className='flash'; document.body.appendChild(f); }
    f.textContent=msg; f.classList.add('show');
    clearTimeout(flash._t); flash._t=setTimeout(function(){ f.classList.remove('show'); },2300);
  }

  /* ---------------- LOCAL crypto (PBKDF2 w/ graceful fallback) ---------------- */
  function lsGet(k,def){ try{ var v=localStorage.getItem(k); return v?JSON.parse(v):def; }catch(e){ return def; } }
  function lsSet(k,v){ try{ localStorage.setItem(k,JSON.stringify(v)); return true; }catch(e){ return false; } }

  function hasSubtle(){ return typeof crypto!=='undefined' && crypto.subtle && crypto.getRandomValues; }
  function randHex(n){
    if(crypto && crypto.getRandomValues){ var a=new Uint8Array(n); crypto.getRandomValues(a); return hex(a.buffer); }
    var s=''; for(var i=0;i<n*2;i++) s+=Math.floor(Math.random()*16).toString(16); return s;
  }
  async function pbkdf2(pass, saltHex, iters){
    if(hasSubtle()){
      var enc=new TextEncoder();
      var salt=new Uint8Array(saltHex.match(/../g).map(function(h){return parseInt(h,16);}));
      var key=await crypto.subtle.importKey('raw',enc.encode(pass),{name:'PBKDF2'},false,['deriveBits']);
      var bits=await crypto.subtle.deriveBits({name:'PBKDF2',salt:salt,iterations:iters,hash:'SHA-256'},key,256);
      return hex(bits);
    }
    // weak fallback (no WebCrypto): clearly insufficient — local convenience only
    var h=0, str=saltHex+'|'+pass+'|'+iters;
    for(var i=0;i<str.length;i++){ h=((h<<5)-h+str.charCodeAt(i))|0; }
    return 'fallback'+(h>>>0).toString(16);
  }

  /* ---------------- SECURE api helper ---------------- */
  async function api(path, opts){
    opts = opts || {};
    opts.headers = Object.assign({'Content-Type':'application/json'}, opts.headers||{});
    opts.credentials = 'same-origin';
    if(opts.body && typeof opts.body!=='string') opts.body=JSON.stringify(opts.body);
    var r = await fetch(AEGIS._apiBuild(path), opts);
    var data=null; try{ data=await r.json(); }catch(e){}
    if(!r.ok){ var err=new Error((data&&data.error)||('HTTP '+r.status)); err.status=r.status; err.data=data; throw err; }
    return data;
  }

  /* ============================================================
     AUTH
     ============================================================ */
  AEGIS.auth = {
    needsSetup: function(){ return !AEGIS._configured; },
    currentUser: function(){ return AEGIS._user; },

    setup: async function(user, pass){
      user=(user||'').trim();
      if(user.length<3) throw new Error('Username must be at least 3 characters.');
      if((pass||'').length<6) throw new Error('Passphrase must be at least 6 characters.');
      if(AEGIS.MODE==='secure'){
        await api('/setup',{method:'POST',body:{user:user,pass:pass}});
        await api('/login',{method:'POST',body:{user:user,pass:pass}});
        AEGIS._configured=true; AEGIS._user=user; return true;
      }
      var salt=randHex(16), iters=150000;
      var h=await pbkdf2(pass,salt,iters);
      lsSet(LS.cred,{user:user,salt:salt,iters:iters,hash:h,createdAt:Date.now()});
      AEGIS._configured=true; AEGIS._user=user;
      sessionStorage.setItem(LS.session,user);
      return true;
    },

    login: async function(user, pass){
      user=(user||'').trim();
      if(AEGIS.MODE==='secure'){
        await api('/login',{method:'POST',body:{user:user,pass:pass}});
        AEGIS._user=user; return true;
      }
      var cred=lsGet(LS.cred,null);
      if(!cred) throw new Error('No account configured on this device.');
      if(user.toLowerCase()!==cred.user.toLowerCase()) throw new Error('Invalid credentials.');
      var h=await pbkdf2(pass,cred.salt,cred.iters||150000);
      if(h!==cred.hash) throw new Error('Invalid credentials.');
      AEGIS._user=cred.user; sessionStorage.setItem(LS.session,cred.user);
      return true;
    },

    logout: async function(){
      if(AEGIS.MODE==='secure'){ try{ await api('/logout',{method:'POST'}); }catch(e){} }
      else { sessionStorage.removeItem(LS.session); }
      AEGIS._user=null;
    },

    changePass: async function(oldPass, newPass){
      if((newPass||'').length<6) throw new Error('New passphrase must be at least 6 characters.');
      if(AEGIS.MODE==='secure'){ await api('/change-pass',{method:'POST',body:{oldPass:oldPass,newPass:newPass}}); return true; }
      var cred=lsGet(LS.cred,null);
      if(!cred) throw new Error('No account configured.');
      var ho=await pbkdf2(oldPass,cred.salt,cred.iters||150000);
      if(ho!==cred.hash) throw new Error('Current passphrase is incorrect.');
      var salt=randHex(16), iters=150000, hn=await pbkdf2(newPass,salt,iters);
      cred.salt=salt; cred.iters=iters; cred.hash=hn; lsSet(LS.cred,cred);
      return true;
    },

    /* call at top of every protected page */
    require: async function(){
      await AEGIS.ready;
      if(AEGIS.auth.needsSetup() || !AEGIS.auth.currentUser()){
        location.href='index.html'; return false;
      }
      return true;
    }
  };

  /* ============================================================
     CONFIG
     ============================================================ */
  var DEFAULT_CONFIG = {
    suiteName: 'AEGIS',
    orgName: 'Field Security Operations',
    classification: 'Unclassified // Internal Use // Personnel Protection',
    operatorInitials: '',
    homeRegion: ''
  };
  AEGIS.config = {
    get: function(){ return Object.assign({}, DEFAULT_CONFIG, AEGIS._config||{}); },
    set: async function(patch){
      var next=Object.assign({}, AEGIS.config.get(), patch||{});
      if(AEGIS.MODE==='secure'){ await api('/config',{method:'PUT',body:next}); }
      else { lsSet(LS.cfg,next); }
      AEGIS._config=next; AEGIS.applyChrome(); return next;
    }
  };

  /* ============================================================
     GENERIC STORE  (collections of {id,...})
     ============================================================ */
  AEGIS.store = {
    collections: COLLECTIONS,
    list: async function(coll){
      if(AEGIS.MODE==='secure'){ return await api('/collections/'+encodeURIComponent(coll)); }
      return lsGet(LS.coll(coll),[]);
    },
    get: async function(coll,id){
      var all=await AEGIS.store.list(coll);
      return all.find(function(x){return x.id===id;})||null;
    },
    put: async function(coll,obj){
      if(!obj.id) obj.id=uid(coll[0]+'_');
      if(AEGIS.MODE==='secure'){ return await api('/collections/'+encodeURIComponent(coll),{method:'POST',body:obj}); }
      var all=lsGet(LS.coll(coll),[]);
      var i=all.findIndex(function(x){return x.id===obj.id;});
      if(i>=0) all[i]=obj; else all.push(obj);
      lsSet(LS.coll(coll),all); return obj;
    },
    remove: async function(coll,id){
      if(AEGIS.MODE==='secure'){ await api('/collections/'+encodeURIComponent(coll)+'/'+encodeURIComponent(id),{method:'DELETE'}); return; }
      var all=lsGet(LS.coll(coll),[]).filter(function(x){return x.id!==id;});
      lsSet(LS.coll(coll),all);
    },
    replaceAll: async function(coll,arr){
      if(AEGIS.MODE==='secure'){ await api('/collections/'+encodeURIComponent(coll),{method:'PUT',body:{items:arr}}); return; }
      lsSet(LS.coll(coll),arr||[]);
    }
  };

  /* ============================================================
     OSINT links (lives in the shared 'osint' collection)
     ============================================================ */
  AEGIS.OSINT_CATEGORIES = ['Travel Advisories','News & Monitoring','Conflict & Crisis','Health & Hazards','Geospatial & Transit','Verification & Research','Cyber & Comms','Custom'];

  function seedOsint(){
    var s=function(label,url,category,notes){ return {id:uid('o_'),label:label,url:url,category:category,notes:notes||''}; };
    return [
      s('US State Dept — Travel Advisories','https://travel.state.gov/content/travel/en/traveladvisories/traveladvisories.html','Travel Advisories','4-tier country advisory system'),
      s('UK FCDO — Foreign Travel Advice','https://www.gov.uk/foreign-travel-advice','Travel Advisories','Country-by-country UK guidance'),
      s('Government of Canada — Travel Advice','https://travel.gc.ca/travelling/advisories','Travel Advisories',''),
      s('Australia — Smartraveller','https://www.smartraveller.gov.au/destinations','Travel Advisories',''),
      s('ReliefWeb','https://reliefweb.int/updates','Conflict & Crisis','UN OCHA humanitarian situation reporting'),
      s('ACLED — Armed Conflict Data','https://acleddata.com/','Conflict & Crisis','Curated conflict event dataset'),
      s('GDACS — Global Disaster Alerts','https://www.gdacs.org/','Health & Hazards','Multi-hazard early warning'),
      s('WHO — Disease Outbreak News','https://www.who.int/emergencies/disease-outbreak-news','Health & Hazards',''),
      s('USGS — Latest Earthquakes','https://earthquake.usgs.gov/earthquakes/map/','Health & Hazards',''),
      s('FlightRadar24','https://www.flightradar24.com/','Geospatial & Transit','Live air traffic'),
      s('MarineTraffic','https://www.marinetraffic.com/','Geospatial & Transit','Live vessel positions'),
      s('OpenStreetMap','https://www.openstreetmap.org/','Geospatial & Transit',''),
      s('Liveuamap','https://liveuamap.com/','News & Monitoring','Crowd-sourced situation map'),
      s('GDELT Project','https://www.gdeltproject.org/','News & Monitoring','Global event/news monitoring'),
      s('Bellingcat','https://www.bellingcat.com/','Verification & Research','Open-source investigation methods'),
      s('Wayback Machine','https://web.archive.org/','Verification & Research','Archived page snapshots'),
      s('Have I Been Pwned','https://haveibeenpwned.com/','Cyber & Comms','Credential breach checks'),
      s('Downdetector','https://downdetector.com/','Cyber & Comms','Service/comms outage reports')
    ];
  }
  AEGIS.osint = {
    list: function(){ return AEGIS.store.list('osint'); },
    save: function(o){ return AEGIS.store.put('osint',o); },
    remove: function(id){ return AEGIS.store.remove('osint',id); },
    ensureSeed: async function(){
      var cur=await AEGIS.store.list('osint');
      if(!cur || !cur.length){ await AEGIS.store.replaceAll('osint', seedOsint()); }
    },
    resetDefaults: async function(){ await AEGIS.store.replaceAll('osint', seedOsint()); }
  };

  /* ============================================================
     SECURITY FEEDS (server-proxied aggregator; secure mode only)
     ============================================================ */
  AEGIS.feeds = {
    // Curated sources — shown as manual links when no server is available.
    SOURCES: [
      {key:'reliefweb', name:'ReliefWeb', url:'https://reliefweb.int/updates'},
      {key:'gdacs', name:'GDACS Disasters', url:'https://www.gdacs.org/'},
      {key:'unhum', name:'UN Humanitarian', url:'https://news.un.org/en/news/topic/humanitarian-aid'},
      {key:'state', name:'US Travel Advisories', url:'https://travel.state.gov/content/travel/en/traveladvisories/traveladvisories.html'},
      {key:'who', name:'WHO Outbreaks', url:'https://www.who.int/emergencies/disease-outbreak-news'},
      {key:'cisa', name:'CISA Cyber', url:'https://www.cisa.gov/news-events/cybersecurity-advisories'}
    ],
    available: function(){ return AEGIS.MODE==='secure'; },
    list: async function(){
      if(AEGIS.MODE!=='secure') return null;   // browser can't fetch cross-origin RSS without the server proxy
      return await api('/feeds');
    }
  };

  /* ============================================================
     BACKUP / RESTORE (works in both modes)
     ============================================================ */
  AEGIS.backup = async function(){
    var out={ aegis:true, version:AEGIS.version, exported:new Date().toISOString(), config:AEGIS.config.get(), collections:{} };
    for(var i=0;i<COLLECTIONS.length;i++){ out.collections[COLLECTIONS[i]]=await AEGIS.store.list(COLLECTIONS[i]); }
    return out;
  };
  AEGIS.restore = async function(data, merge){
    if(!data || !data.collections) throw new Error('Not a valid AEGIS backup file.');
    if(data.config) await AEGIS.config.set(data.config);
    for(var c in data.collections){
      if(COLLECTIONS.indexOf(c)<0) continue;
      if(merge){
        var cur=await AEGIS.store.list(c);
        var map={}; cur.forEach(function(x){map[x.id]=x;});
        (data.collections[c]||[]).forEach(function(x){map[x.id]=x;});
        await AEGIS.store.replaceAll(c, Object.keys(map).map(function(k){return map[k];}));
      } else {
        await AEGIS.store.replaceAll(c, data.collections[c]||[]);
      }
    }
  };
  AEGIS.downloadBackup = async function(){
    var data=await AEGIS.backup();
    var blob=new Blob([JSON.stringify(data,null,2)],{type:'application/json'});
    var a=document.createElement('a'); a.href=URL.createObjectURL(blob);
    a.download='aegis-backup-'+new Date().toISOString().slice(0,10)+'.json'; a.click();
  };

  /* ============================================================
     CHROME (banners, org name, DTG ticker)
     ============================================================ */
  AEGIS.applyChrome = function(){
    var cfg=AEGIS.config.get();
    document.querySelectorAll('[data-aegis-class]').forEach(function(el){ el.textContent=cfg.classification; });
    document.querySelectorAll('[data-aegis-org]').forEach(function(el){ el.textContent=cfg.orgName; });
    document.querySelectorAll('[data-aegis-suite]').forEach(function(el){ el.textContent=cfg.suiteName; });
  };
  AEGIS.startDtg=function(){
    var tick=function(){ document.querySelectorAll('[data-aegis-dtg]').forEach(function(el){ el.textContent=dtgNow(); }); };
    tick(); setInterval(tick,15000);
  };

  /* ============================================================
     BOOT  — detect mode, load config + auth state
     ============================================================ */
  async function detectMode(){
    // Candidate URL builders, tried in order:
    //   1. clean URLs            /api/status            (needs URL rewriting)
    //   2. query-string routing  /api/index.php?__route=status   (works on ANY PHP host —
    //      no rewrite, no PATH_INFO required)
    var candidates=[
      function(p){ return '/api'+p; },
      function(p){ return '/api/index.php?__route='+p.replace(/^\//,''); }
    ];
    for(var i=0;i<candidates.length;i++){
      try{
        var ctrl=new AbortController(); var t=setTimeout(function(){ctrl.abort();},1600);
        var r=await fetch(candidates[i]('/status'),{signal:ctrl.signal,credentials:'same-origin'});
        clearTimeout(t);
        if(r.ok){
          var s=await r.json();
          if(s && s.mode==='secure'){
            AEGIS._apiBuild=candidates[i];
            AEGIS.MODE='secure'; AEGIS._configured=!!s.configured; AEGIS._user=s.user||null;
            AEGIS._config=s.config||null; return;
          }
        }
      }catch(e){ /* try next candidate, then fall through to local */ }
    }
    AEGIS.MODE='local';
    var cred=lsGet(LS.cred,null);
    AEGIS._configured=!!cred;
    AEGIS._user=sessionStorage.getItem(LS.session)||null;
    AEGIS._config=lsGet(LS.cfg,null);
  }

  AEGIS.ready = detectMode();

  /* ============================================================
     THEME (per-device preference: 'dark' default, 'light')
     ============================================================ */
  AEGIS.theme = {
    get: function(){ try{ return localStorage.getItem('aegis.theme')||'dark'; }catch(e){ return 'dark'; } },
    apply: function(t){ document.documentElement.dataset.theme = t || AEGIS.theme.get(); },
    set: function(t){ try{ localStorage.setItem('aegis.theme',t); }catch(e){} AEGIS.theme.apply(t); },
    toggle: function(){ AEGIS.theme.set(AEGIS.theme.get()==='dark' ? 'light' : 'dark'); }
  };
  AEGIS.theme.apply();

  /* expose helpers */
  AEGIS.esc=esc; AEGIS.uid=uid; AEGIS.flash=flash; AEGIS.dtgNow=dtgNow;
  global.AEGIS=AEGIS;
})(window);
