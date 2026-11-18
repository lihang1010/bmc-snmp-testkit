/* MIB browser: expandable OID tree on the left, table/raw results on the right.
   Plain JS on purpose - the whole service is offline/intranet with no CDN deps. */
(function(){
  'use strict';

  var $ = function(id){ return document.getElementById(id); };
  function esc(s){
    return String(s == null ? '' : s).replace(/[&<>"]/g, function(c){
      return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];
    });
  }
  function api(path, opts){
    opts = opts || {};
    opts.credentials = 'same-origin';
    opts.headers = Object.assign({'Content-Type':'application/json'}, opts.headers || {});
    return fetch(path, opts).then(function(r){
      return r.json().catch(function(){ return {}; }).then(function(d){
        if(!r.ok) throw new Error((d && d.detail) || ('HTTP ' + r.status));
        return d;
      });
    });
  }
  var toastTimer = null;
  function toast(msg, bad){
    var t = $('toast');
    t.textContent = msg; t.className = bad ? 'bad' : '';
    t.style.display = 'block';
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function(){ t.style.display = 'none'; }, 4200);
  }
  function setProbeStatus(text, state){
    var el = $('probeStatus');
    if(!el) return;
    if(state === 'hidden'){ el.classList.add('hidden'); return; }
    el.classList.remove('hidden');
    el.classList.toggle('ok', state === 'ok');
    el.classList.toggle('fail', state === 'fail');
    $('probeSpinner').classList.toggle('hidden', state !== 'busy');
    $('probeStatusText').textContent = text;
    el.title = text;
  }

  var treeData = null;          // {nodes, tables, module_name, root_oid, total}
  var currentMibId = '';        // mib_id of the tree currently shown
  var byName = {};              // name -> node
  var childrenMap = {};         // parent_name -> [nodes], sorted by sub_id
  var roots = [];               // nodes whose parent is outside the model
  var expanded = {};            // node.oid -> true (lazy child rendering)
  var prefixMap = {};           // column oid -> {name, table_name}
  var tableCols = {};           // table_name -> [{oid, name}]
  var colSyntax = {};           // column oid -> syntax (for enum value labels)
  var allOidMap = {};           // node oid -> node (for numeric OID -> name)
  var showAll = {};             // node.oid -> true (expand a huge child list fully)
  var instanceRows = {};        // table_name -> [row_index], discovered at WALK time
  var tableIndexNames = {};     // table_name -> INDEX { ... } symbol names
  var selected = null;
  var lastResult = null, lastRequest = null, viewMode = 'smart', busy = false;
  var refreshTimer = null, ctxNode = null;
  var caps = null, pendingSetOid = null;
  var MAX_PAGES = 10;

  var ICONS = {group:'▦', table:'▤', entry:'▧', column:'▪', scalar:'•',
               instances:'▥', row:'›'};
  function kindIcon(kind){ return ICONS[kind] || '·'; }
  function keyOf(node){ return node.__key || node.oid; }

  // ------------------------------------------------------------- MIB list + tree
  function loadMibs(){
    return api('/api/mibs').then(function(d){
      var mibs = d.mibs || [];
      $('mibSelect').innerHTML = mibs.length
        ? mibs.map(function(m){
            return '<option value="'+esc(m.mib_id)+'">'+esc(m.filename)+' · '+m.node_count+' 节点</option>';
          }).join('')
        : '<option value="">暂无 MIB，请先在控制台上传</option>';
      if(mibs.length) return loadTree(mibs[0].mib_id);
      currentMibId = '';
      $('treeInfo').textContent = '未上传 MIB';
      $('tree').innerHTML = '<div class="tree-empty">尚未上传 MIB，请先在控制台上传并解析</div>';
      $('statusPill').textContent = '未上传 MIB';
    }).catch(function(e){ toast('加载 MIB 失败: '+e.message, true); });
  }

  function loadTree(mibId){
    currentMibId = mibId;
    $('treeInfo').textContent = '加载节点树…';
    $('tree').innerHTML = '<div class="tree-empty">加载中…</div>';
    return api('/api/mibs/'+mibId+'/tree').then(function(d){
      treeData = d;
      instanceRows = {};
      buildTreeIndex(d.nodes || []);
      selected = null;
      $('nodeDetail').innerHTML = '';
      renderTree();
      $('treeInfo').innerHTML = '共 <b>'+d.total+'</b> 个节点 · '+esc(d.module_name || '')+
        ' · 单击标量/表/列自动探测';
      $('statusPill').textContent = (d.module_name || 'MIB') + ' · ' + d.total + ' 节点';
      return api('/api/mibs/'+mibId+'/warnings').then(function(w){
        var bits = [];
        if(w.total){
          var first = (w.warnings || []).slice(0, 3).map(function(x){
            return (x.code || '') + ' ' + (x.message || '');
          }).join('；');
          bits.push('解析告警 ' + w.total + ' 条（前 3 条：' + first + '）');
        }
        var p = w.parser || {};
        var deps = Object.keys(p.imports || {});
        if(deps.length) bits.push('IMPORTS 依赖模块：' + deps.join(', '));
        if(p.strict_ok === false) bits.push('未通过 SMIv2 严格语法检查，已用容错解析器解析');
        var box = $('parseWarn');
        box.innerHTML = bits.map(esc).join('<br>');
        box.classList.toggle('hidden', !bits.length);
      }).catch(function(){});
    }).catch(function(e){
      $('tree').innerHTML = '<div class="tree-empty">加载失败: '+esc(e.message)+'</div>';
      toast('加载节点树失败: '+e.message, true);
    });
  }

  function buildTreeIndex(nodes){
    byName = {}; childrenMap = {}; prefixMap = {}; tableCols = {};
    colSyntax = {}; allOidMap = {}; showAll = {}; expanded = {};
    tableIndexNames = {};
    (treeData.tables || []).forEach(function(t){
      tableIndexNames[t.name] = t.index_names || [];
    });
    nodes.forEach(function(n){ byName[n.name] = n; });
    nodes.forEach(function(n){
      (childrenMap[n.parent_name] = childrenMap[n.parent_name] || []).push(n);
      if(n.oid) allOidMap[n.oid] = n;
      if(n.kind === 'column' && n.oid){
        prefixMap[n.oid] = {name:n.name, table_name:n.table_name};
        colSyntax[n.oid] = n.syntax;
        (tableCols[n.table_name] = tableCols[n.table_name] || []).push({oid:n.oid, name:n.name});
      }
    });
    Object.keys(childrenMap).forEach(function(k){
      childrenMap[k].sort(function(a,b){ return (a.sub_id||0) - (b.sub_id||0); });
    });
    roots = nodes.filter(function(n){ return !byName[n.parent_name]; });
    roots.sort(function(a,b){ return (a.sub_id||0) - (b.sub_id||0); });
    roots.forEach(function(n){ expanded[n.oid] = true; });
  }

  function makeNodeRow(node, depth, hasKids){
    var row = document.createElement('div');
    var key = keyOf(node);
    row.className = 'tree-node' + (selected && selected.name === node.name ? ' selected' : '');
    row.style.paddingLeft = (8 + depth*14) + 'px';

    var toggle = document.createElement('span');
    toggle.className = 'tree-toggle' + (hasKids ? '' : ' leaf');
    toggle.textContent = expanded[key] ? '▼' : '▶';
    if(hasKids){
      toggle.addEventListener('click', function(e){
        e.stopPropagation();
        expanded[key] = !expanded[key];
        renderTree();
      });
    }
    row.appendChild(toggle);

    var icon = document.createElement('span');
    icon.className = 'tree-icon ' + esc(node.kind || 'group');
    icon.textContent = kindIcon(node.kind);
    row.appendChild(icon);

    var name = document.createElement('span');
    name.className = 'tree-name';
    name.textContent = node.name;
    name.title = node.name + ' · ' + node.oid;
    row.appendChild(name);

    if(node.kind === 'column' || node.kind === 'scalar'){
      var acc = document.createElement('span');
      acc.className = 'tree-access';
      acc.textContent = node.access || '';
      row.appendChild(acc);
    }
    var oid = document.createElement('span');
    oid.className = 'tree-oid';
    oid.textContent = node.oid || '';
    row.appendChild(oid);

    row.__node = node;
    row.addEventListener('click', function(){
      if(node.__synthetic === 'row') showInstanceDetail(node.__table, node.__index);
      else selectNode(node);
    });
    row.addEventListener('dblclick', function(e){
      if(e.target.classList.contains('tree-toggle')) return;
      probeNode(node);
    });
    return row;
  }

  // Static model children plus instances discovered by the last WALK.  The MIB
  // model has no instance layer, so these nodes are synthetic and are keyed
  // separately to avoid colliding with the parent's real OID.
  function childrenOf(node){
    if(node.__synthetic === 'instances'){
      return (node.__rows || []).map(function(ix){
        return {__synthetic:'row', __key:node.oid + '#row#' + ix,
                name:'行 ' + ix, oid:node.oid + '.' + ix, kind:'row',
                __table:node.__table, __index:ix};
      });
    }
    var kids = (childrenMap[node.name] || []).slice();
    if(node.kind === 'table'){
      var idxs = instanceRows[node.name] || [];
      if(idxs.length){
        kids.push({__synthetic:'instances', __key:node.oid + '#instances',
                   name:'实例 (' + idxs.length + ')', oid:node.oid, kind:'instances',
                   __rows:idxs, __table:node.name});
      }
    }
    return kids;
  }

  function makeTreeNode(node, depth){
    var wrap = document.createElement('div');
    var key = keyOf(node);
    var kids = childrenOf(node);
    wrap.appendChild(makeNodeRow(node, depth, kids.length > 0));
    var holder = document.createElement('div');
    holder.style.display = expanded[key] ? 'block' : 'none';
    if(expanded[key] && kids.length){
      // Lazy + chunked: only expanded levels are built, and a single level with
      // hundreds of nodes is capped until the user asks for the rest.
      var limit = showAll[key] ? kids.length : 60;
      kids.slice(0, limit).forEach(function(c){
        holder.appendChild(makeTreeNode(c, depth+1));
      });
      if(kids.length > limit){
        var more = document.createElement('div');
        more.className = 'tree-more';
        more.style.paddingLeft = (8 + (depth+1)*14) + 'px';
        more.textContent = '… 还有 ' + (kids.length - limit) + ' 个节点，点击全部展开';
        more.addEventListener('click', function(){
          showAll[key] = true; renderTree();
        });
        holder.appendChild(more);
      }
    }
    wrap.appendChild(holder);
    return wrap;
  }

  function renderTree(){
    if(!treeData) return;
    var q = ($('treeQuery').value || '').trim().toLowerCase();
    var box = $('tree');
    box.innerHTML = '';
    if(q){
      var matches = (treeData.nodes || []).filter(function(n){
        return (n.name || '').toLowerCase().indexOf(q) >= 0 || (n.oid || '').indexOf(q) >= 0;
      });
      if(!matches.length){ box.innerHTML = '<div class="tree-empty">没有匹配的节点</div>'; return; }
      matches.slice(0, 300).forEach(function(n){ box.appendChild(makeNodeRow(n, 1, false)); });
      if(matches.length > 300){
        var more = document.createElement('div');
        more.className = 'tree-empty';
        more.textContent = '仅显示前 300 条（共 ' + matches.length + ' 条）';
        box.appendChild(more);
      }
      return;
    }
    var title = document.createElement('div');
    title.className = 'tree-node';
    title.style.cursor = 'default';
    title.innerHTML = '<span class="tree-icon group">▦</span><span class="tree-name">'+
      esc(treeData.module_name || 'MIB 树')+'</span><span class="tree-oid">'+
      esc(treeData.root_oid || '')+'</span>';
    box.appendChild(title);
    roots.forEach(function(n){ box.appendChild(makeTreeNode(n, 1)); });
  }

  function showNodeDetail(n){
    var parts = ['<b>'+esc(n.name)+'</b> · '+esc(n.kind)+' · access '+esc(n.access || '-'),
                 'OID <code>'+esc(n.oid)+'</code>'];
    if(n.table_name) parts.push('所属表 <b>'+esc(n.table_name)+'</b>');
    if(n.index_names && n.index_names.length) parts.push('索引 '+esc(n.index_names.join(', ')));
    if(n.syntax){
      var s = n.syntax, txt = s.base_type || '';
      if(s.enum && Object.keys(s.enum).length){
        txt += ' · 枚举 '+Object.keys(s.enum).map(function(k){ return k+'='+s.enum[k]; }).join(', ');
      }
      if(s.ranges && s.ranges.length) txt += ' · 范围 '+s.ranges.map(function(r){ return r.join('..'); }).join(',');
      if(s.size && s.size.length) txt += ' · 长度 '+s.size.join('..');
      parts.push('语法 '+esc(txt));
    }
    $('nodeDetail').innerHTML = parts.join('<br>');
  }

  function selectNode(node){
    selected = node;
    renderTree();
    showNodeDetail(node);
    var oid = node.oid || '';
    if(node.kind === 'scalar'){
      $('oid').value = oid ? oid + '.0' : '';
    } else {
      $('oid').value = oid;
      if(node.kind === 'table' || node.kind === 'entry') setView('smart');
    }
  }

  // Single click only selects; double click (or toolbar/context menu) probes.
  function probeNode(node){
    if(!node) return;
    if(node.__synthetic === 'row'){
      var cols = tableCols[node.__table] || [];
      var first = cols[0];
      var rowOid = first ? (first.oid + '.' + node.__index) : node.oid;
      $('oid').value = rowOid;
      runProbe('GET', rowOid);
      return;
    }
    if(node.__synthetic === 'instances'){
      $('oid').value = node.oid;
      runProbe('WALK', node.oid);
      return;
    }
    var oid = node.oid || '';
    if(!oid) return;
    if(node.kind === 'scalar'){
      $('oid').value = oid + '.0';
      runProbe('GET', oid + '.0');
    } else {
      $('oid').value = oid;
      if(node.kind === 'table' || node.kind === 'entry') setView('smart');
      runProbe('WALK', oid);
    }
  }

  // ------------------------------------------------------------- probe
  function payload(operation, oid, extra){
    var version = $('version').value;
    var cred = version === 'v3'
      ? {v3_user:$('v3user').value, security_level:$('securityLevel').value,
         auth_protocol:$('authProtocol').value, priv_protocol:$('privProtocol').value,
         auth_key:$('authKey').value, priv_key:$('privKey').value}
      : {community:$('community').value};
    var body = {
      mode: 'live',
      target_host: $('host').value.trim(),
      target_port: parseInt($('port').value || '161', 10),
      version: version, credential: cred, operation: operation, oid: oid,
      max_results: parseInt($('maxResults').value || '200', 10)
    };
    if(currentMibId) body.mib_id = currentMibId;
    if(operation === 'SET'){
      body.value = (extra && extra.value) || '';
      body.asn1 = (extra && extra.asn1) || 'OctetString';
    }
    return body;
  }

  // WALK continuation: oid stays the subtree root, cursor is the resume point.
  function walkPage(b, acc, pages){
    return api('/api/snmp/probe', {method:'POST', body:JSON.stringify(b)}).then(function(d){
      if(!acc){ acc = Object.assign({}, d); acc.varbinds = (d.varbinds || []).slice(); }
      else{
        acc.count += d.count;
        acc.varbinds = acc.varbinds.concat(d.varbinds || []);
        acc.elapsed_ms += d.elapsed_ms;
        acc.truncated = d.truncated;
        if(!d.ok){ acc.ok = false; acc.error = d.error; }
      }
      if(b.operation === 'WALK'){
        var progress = 'WALK 中… 已取 ' + acc.count + ' 条（第 ' + pages + ' 页）';
        setProbeStatus(progress, 'busy');
        $('resultMeta').innerHTML = '<span class="muted">' + esc(progress) + '</span>';
      }
      if(d.ok && b.operation === 'WALK' && d.truncated && d.next_cursor &&
         (d.varbinds || []).length && pages < MAX_PAGES){
        return walkPage(Object.assign({}, b, {cursor:d.next_cursor}), acc, pages+1);
      }
      return acc;
    });
  }

  function setButtons(disabled){
    ['getBtn','nextBtn','walkBtn','tableBtn','setBtn','refreshBtn','exportBtn'].forEach(function(id){
      $(id).disabled = disabled;
    });
    if(!disabled) syncSetButton();
  }

  function runProbe(operation, oid, extra){
    if(!oid){ toast('请填写 OID', true); return; }
    if(busy){ toast('正在探测中，请稍候', true); return; }
    var body = payload(operation, oid, extra);
    if(operation === 'SET' && !String(body.value || '')){
      toast('请填写 SET 值', true); return;
    }
    if(!body.target_host){
      toast('请填写目标 IP', true); return;
    }
    if(body.version === 'v3'){
      if(!body.credential.v3_user){ toast('v3 模式请填写用户名', true); return; }
    } else if(!body.credential.community){
      toast('请填写团体字', true); return;
    }
    lastRequest = body;
    busy = true; setButtons(true);
    var opBtn = {GET:'getBtn', GETNEXT:'nextBtn', WALK:'walkBtn', SET:'setBtn'}[operation];
    if(opBtn) $(opBtn).classList.add('is-loading');
    setProbeStatus(operation === 'WALK' ? 'WALK 中…（长表可能需要数秒）' : operation + ' 请求中…', 'busy');
    $('resultMeta').innerHTML = '<span class="muted">探测中… '+esc(operation)+' '+esc(oid)+'</span>';
    walkPage(body, null, 1).then(function(d){
      lastResult = d;
      renderResult(d);
      if(!d.ok){
        toast('探测返回错误: '+(d.error || ''), true);
        setProbeStatus(operation + ' 失败 · '+(d.error || '未知错误'), 'fail');
      } else {
        setProbeStatus(operation + ' 完成 · '+d.count+' 条 · '+Math.round(d.elapsed_ms)+' ms', 'ok');
        if(operation === 'SET') toast('SET 已执行，建议 GET/刷新读回确认');
      }
    }).catch(function(e){
      toast('探测失败: '+e.message, true);
      setProbeStatus(operation + ' 失败 · '+e.message, 'fail');
      $('resultMeta').innerHTML = '<span class="badge badge--fail">失败</span><span>'+esc(e.message)+'</span>';
    }).finally(function(){
      busy = false; setButtons(false);
      if(opBtn) $(opBtn).classList.remove('is-loading');
    });
  }

  // ------------------------------------------------------------- result views
  function renderMeta(d){
    var m = '<span class="badge '+(d.ok?'badge--ok':'badge--fail')+'">'+(d.ok?'成功':'失败')+'</span>'+
      '<span>操作 <b>'+esc(d.operation)+'</b></span>'+
      '<span>OID <b>'+esc(d.oid)+'</b></span>'+
      '<span>目标 <b>'+esc(d.target)+'</b></span>'+
      '<span>返回 <b>'+d.count+'</b> 条</span>'+
      '<span>耗时 <b>'+d.elapsed_ms+' ms</b></span>'+
      (d.truncated?'<span class="badge badge--fail">已达条数上限</span>':'')+
      (d.error?'<span>错误 <b style="color:var(--fail)">'+esc(d.error)+'</b></span>':'');
    $('resultMeta').innerHTML = m;
  }

  function groupTables(varbinds){
    var tables = {}, scalars = [], prefixes = Object.keys(prefixMap);
    varbinds.forEach(function(vb){
      var bestLen = -1, bestInfo = null;
      prefixes.forEach(function(p){
        if(vb.oid.length > p.length && vb.oid.indexOf(p+'.') === 0 && p.length > bestLen){
          bestLen = p.length; bestInfo = prefixMap[p];
        }
      });
      if(bestInfo){
        var idx = vb.oid.slice(bestLen+1);
        var t = tables[bestInfo.table_name] || (tables[bestInfo.table_name] = {rows:{}});
        (t.rows[idx] = t.rows[idx] || {})[bestInfo.name] = vb;
      } else {
        scalars.push(vb);
      }
    });
    return {tables:tables, scalars:scalars};
  }

  function renderTableBlock(name, t){
    var colDefs = tableCols[name] || [];
    var idxs = Object.keys(t.rows);
    var html = '<div class="tbl-block"><div class="tbl-title">表 <code>'+esc(name)+'</code> '+
      '<span class="cnt">· '+idxs.length+' 行 / '+colDefs.length+' 列</span></div>';
    html += '<div class="table-scroll"><table><thead><tr><th>索引</th>';
    colDefs.forEach(function(c){ html += '<th>'+esc(c.name)+'</th>'; });
    html += '</tr></thead><tbody>';
    idxs.forEach(function(ix){
      html += '<tr data-table="'+esc(name)+'" data-index="'+esc(ix)+'" title="点击查看该行完整 OID"><td><code>'+esc(ix)+'</code></td>';
      colDefs.forEach(function(c){
        var vb = t.rows[ix][c.name];
        html += vb ? '<td class="value" title="'+esc(vb.oid)+'">'+esc(formatValue(vb, c.oid))+'</td>'
                   : '<td class="muted">—</td>';
      });
      html += '</tr>';
    });
    html += '</tbody></table></div></div>';
    return html;
  }

  function rawRowsHtml(rows){
    if(!rows.length) return '';
    var html = '<div class="table-scroll"><table><thead><tr><th>OID</th><th>类型</th><th>值</th><th>异常</th></tr></thead><tbody>';
    rows.forEach(function(v){
      html += '<tr><td><code>'+esc(v.oid)+'</code><div class="muted" style="font-size:10.5px">'+
        esc(oidLabel(v.oid))+'</div></td><td>'+esc(v.type)+'</td>'+
        '<td class="value">'+esc(formatValue(v, colOidOf(v.oid)))+'</td><td>'+
        (v.exception ? '<span style="color:var(--fail)">'+esc(v.exception)+'</span>' : '<span class="muted">—</span>')+
        '</td></tr>';
    });
    return html + '</tbody></table></div>';
  }

  function renderBody(){
    var d = lastResult;
    if(!d) return;
    var grouped = groupTables(d.varbinds || []);
    var names = Object.keys(grouped.tables);
    var html = '';
    if(d.truncated){
      html += '<div class="note warn">结果已达安全上限仍未取尽，表格可能不完整；可缩小 OID 范围分列查看。</div>';
    }
    if(viewMode !== 'raw' && names.length){
      names.forEach(function(n){ html += renderTableBlock(n, grouped.tables[n]); });
    }
    if(viewMode !== 'tableonly'){
      var rows = (viewMode === 'raw') ? (d.varbinds || []) : grouped.scalars;
      var label = (viewMode === 'raw') ? '原始 OID 列表' : (names.length ? '其他（非表）节点' : '返回值');
      if(rows.length){
        html += '<div class="tbl-block"><div class="tbl-title">'+esc(label)+
          ' <span class="cnt">· '+rows.length+' 条</span></div>'+rawRowsHtml(rows)+'</div>';
      }
    }
    $('resultScroll').innerHTML = html || '<div class="empty">没有返回数据</div>';
  }

  function renderResult(d){
    lastResult = d;
    instanceRows = {};
    var grouped = groupTables(d.varbinds || []);
    Object.keys(grouped.tables).forEach(function(name){
      instanceRows[name] = Object.keys(grouped.tables[name].rows);
    });
    renderMeta(d);
    renderBody();
    renderTree();
  }

  function colOidOf(oid){
    var best = null, bestLen = -1;
    Object.keys(prefixMap).forEach(function(p){
      if(oid.length > p.length && oid.indexOf(p+'.') === 0 && p.length > bestLen){
        bestLen = p.length; best = p;
      }
    });
    return best;
  }

  function oidLabel(oid){
    var best = null, bestLen = -1;
    Object.keys(allOidMap).forEach(function(p){
      if((oid === p || oid.indexOf(p+'.') === 0) && p.length > bestLen){
        bestLen = p.length; best = allOidMap[p];
      }
    });
    return best ? best.name + (oid.length > bestLen ? oid.slice(bestLen) : '') : oid;
  }

  function formatValue(vb, colOid){
    var val = vb.value;
    var syn = colOid ? colSyntax[colOid] : null;
    if(syn && syn.enum && Object.keys(syn.enum).length){
      var label = null;
      Object.keys(syn.enum).forEach(function(k){
        if(String(syn.enum[k]) === String(val)) label = k;
      });
      if(label) return label + ' (' + val + ')';
    }
    return val;
  }

  function csvCell(s){
    var t = String(s == null ? '' : s);
    return /[",\n]/.test(t) ? '"' + t.replace(/"/g, '""') + '"' : t;
  }

  function exportCsv(){
    if(!lastResult || !(lastResult.varbinds || []).length){
      toast('没有可导出的数据', true); return;
    }
    var grouped = groupTables(lastResult.varbinds || []);
    var lines = [];
    Object.keys(grouped.tables).forEach(function(name){
      var cols = tableCols[name] || [];
      lines.push('# 表 ' + name);
      lines.push(['索引'].concat(cols.map(function(c){ return c.name; })).map(csvCell).join(','));
      Object.keys(grouped.tables[name].rows).forEach(function(ix){
        var row = grouped.tables[name].rows[ix];
        lines.push([ix].concat(cols.map(function(c){
          return row[c.name] ? formatValue(row[c.name], c.oid) : '';
        })).map(csvCell).join(','));
      });
      lines.push('');
    });
    if(grouped.scalars.length){
      lines.push('# 其他节点');
      lines.push(['OID', '节点名', '类型', '值', '异常'].map(csvCell).join(','));
      grouped.scalars.forEach(function(v){
        lines.push([v.oid, oidLabel(v.oid), v.type,
                    formatValue(v, colOidOf(v.oid)), v.exception || ''].map(csvCell).join(','));
      });
    }
    var blob = new Blob(['\ufeff' + lines.join('\n')], {type:'text/csv;charset=utf-8'});
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url; a.download = 'mib-browser.csv';
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    setTimeout(function(){ URL.revokeObjectURL(url); }, 1000);
    toast('已导出 mib-browser.csv');
  }

  // Rows only exist at WALK time (the model has no instance layer); both the
  // synthetic instance tree nodes and the table rows show the same detail view.
  function indexLabel(name, ix){
    var names = tableIndexNames[name] || [];
    if(!names.length) return '';
    var parts = String(ix).split('.');
    // Only pure-integer indexes can be decoded safely.  String/IP/OID indexes
    // use length-prefixed or ASN.1 encodings the model does not describe.
    if(parts.length !== names.length || !parts.every(function(p){ return /^\d+$/.test(p); })){
      return '复合索引（未解码）: ' + ix;
    }
    return names.map(function(n, i){ return n + '=' + parts[i]; }).join(', ');
  }

  function rowDetailHtml(name, ix){
    var t = lastResult ? groupTables(lastResult.varbinds || []).tables[name] : null;
    if(!t || !t.rows[ix]) return '';
    var parts = ['<b>'+esc(name)+'</b> · 索引 <code>'+esc(ix)+'</code>'];
    var label = indexLabel(name, ix);
    if(label) parts.push('索引解释 ' + esc(label));
    (tableCols[name] || []).forEach(function(c){
      var vb = t.rows[ix][c.name];
      if(vb) parts.push(esc(c.name)+' = <b>'+esc(formatValue(vb, c.oid))+'</b> <code>'+esc(vb.oid)+'</code>');
    });
    return parts.join('<br>');
  }

  function showInstanceDetail(name, ix){
    $('nodeDetail').innerHTML = rowDetailHtml(name, ix);
    document.querySelectorAll('#resultScroll tr[data-table][data-index]').forEach(function(tr){
      tr.classList.toggle('row-hi', tr.dataset.table === name && tr.dataset.index === ix);
    });
  }

  $('resultScroll').addEventListener('click', function(e){
    var tr = e.target.closest('tr[data-table][data-index]');
    if(tr) showInstanceDetail(tr.dataset.table, tr.dataset.index);
  });

  function setView(mode){
    viewMode = mode;
    document.querySelectorAll('input[name="view"]').forEach(function(r){
      r.checked = (r.value === mode);
    });
    renderBody();
  }

  // ------------------------------------------------------------- bindings
  document.querySelectorAll('input[name="view"]').forEach(function(r){
    r.addEventListener('change', function(){ setView(this.value); });
  });
  $('mibSelect').addEventListener('change', function(){ loadTree(this.value); });
  var queryTimer = null;
  $('treeQuery').addEventListener('input', function(){
    clearTimeout(queryTimer);
    queryTimer = setTimeout(renderTree, 250);
  });
  function syncVersion(){
    var isV3 = $('version').value === 'v3';
    $('v3box').classList.toggle('hidden', !isV3);
    $('communityBox').classList.toggle('hidden', isV3);
    $('connGrid').classList.toggle('v3-mode', isV3);
  }
  $('version').addEventListener('change', syncVersion);
  syncVersion();
  $('getBtn').addEventListener('click', function(){ runProbe('GET', $('oid').value.trim()); });
  $('nextBtn').addEventListener('click', function(){ runProbe('GETNEXT', $('oid').value.trim()); });
  $('walkBtn').addEventListener('click', function(){ runProbe('WALK', $('oid').value.trim()); });
  $('tableBtn').addEventListener('click', function(){
    setView('smart');
    runProbe('WALK', $('oid').value.trim());
  });
  $('refreshBtn').addEventListener('click', function(){
    if(!lastRequest){ toast('还没有可刷新的探测', true); return; }
    // Never replay a SET on refresh: read the value back instead.
    var op = lastRequest.operation === 'SET' ? 'GET' : lastRequest.operation;
    runProbe(op, lastRequest.oid);
  });
  $('oid').addEventListener('keydown', function(e){
    if(e.key === 'Enter') runProbe('WALK', this.value.trim());
  });
  $('exportBtn').addEventListener('click', exportCsv);

  // ---- SET (explicit confirmation; the server also enforces hard blocks) ----
  function syncSetButton(){
    var blocked = caps && (caps.live_set === false || caps.set_enabled === false);
    $('setBtn').disabled = !!blocked;
    $('setBtn').title = blocked
      ? '服务策略已禁用 live SET（security.web.live_set_enabled=false）' : '';
  }
  function loadCaps(){
    return api('/api/snmp/capabilities').then(function(d){
      caps = d; syncSetButton();
    }).catch(function(){ /* keep buttons usable if capabilities are unavailable */ });
  }
  function closeSetDialog(){ $('setDialog').classList.add('hidden'); }
  function openSetDialog(oid){
    if(!oid){ toast('请先选择节点或填写 OID', true); return; }
    if($('setBtn').disabled){ toast('服务策略已禁用 live SET', true); return; }
    pendingSetOid = oid;
    $('oid').value = oid;
    var target = ($('host').value.trim() || '(未填目标)') + ':' + ($('port').value || '161');
    $('setText').textContent = '将向 ' + target + ' 写入 ' + oid + ' = ' +
      ($('setValue').value || '(空)') + '（' + $('setAsn1').value + '）。' +
      '这会修改真实设备配置，请再次确认。';
    $('setDialog').classList.remove('hidden');
    $('setValue').focus();
  }
  $('setBtn').addEventListener('click', function(){ openSetDialog($('oid').value.trim()); });
  $('setCancel').addEventListener('click', closeSetDialog);
  $('setBackdrop').addEventListener('click', closeSetDialog);
  function refreshSetText(){
    if($('setDialog').classList.contains('hidden') || !pendingSetOid) return;
    var target = ($('host').value.trim() || '(未填目标)') + ':' + ($('port').value || '161');
    $('setText').textContent = '将向 ' + target + ' 写入 ' + pendingSetOid + ' = ' +
      ($('setValue').value || '(空)') + '（' + $('setAsn1').value + '）。' +
      '这会修改真实设备配置，请再次确认。';
  }
  $('setValue').addEventListener('input', refreshSetText);
  $('setValue').addEventListener('keydown', function(e){
    if(e.key === 'Enter'){ e.preventDefault(); $('setOk').click(); }
  });
  $('setAsn1').addEventListener('change', refreshSetText);
  $('setOk').addEventListener('click', function(){
    var v = $('setValue').value, t = $('setAsn1').value;
    if(!v){ toast('请填写 SET 值', true); return; }
    closeSetDialog();
    if(pendingSetOid) runProbe('SET', pendingSetOid, {value:v, asn1:t});
  });
  document.addEventListener('keydown', function(e){
    if(e.key === 'Escape') closeSetDialog();
  });

  $('autoRefresh').addEventListener('change', function(){
    clearInterval(refreshTimer); refreshTimer = null;
    if(this.checked){
      var secs = Math.max(2, Math.min(600, parseInt($('refreshSeconds').value || '10', 10)));
      refreshTimer = setInterval(function(){
        if(!busy && lastRequest){
          var op = lastRequest.operation === 'SET' ? 'GET' : lastRequest.operation;
          runProbe(op, lastRequest.oid);
        }
      }, secs * 1000);
      toast('已开启自动刷新（每 ' + secs + ' 秒）');
    }
  });
  $('refreshSeconds').addEventListener('change', function(){
    if($('autoRefresh').checked) $('autoRefresh').dispatchEvent(new Event('change'));
  });

  function copyText(t){
    if(navigator.clipboard && navigator.clipboard.writeText){
      navigator.clipboard.writeText(t).then(function(){ toast('已复制: ' + t); });
    } else {
      toast(t);
    }
  }
  $('tree').addEventListener('contextmenu', function(e){
    var row = e.target.closest('.tree-node');
    if(!row || !row.__node) return;
    e.preventDefault();
    ctxNode = row.__node;
    var menu = $('contextMenu');
    menu.classList.remove('hidden');
    menu.style.left = Math.min(e.clientX, window.innerWidth - 190) + 'px';
    menu.style.top = Math.min(e.clientY, window.innerHeight - 230) + 'px';
  });
  $('contextMenu').addEventListener('click', function(e){
    var item = e.target.closest('.ctx-item');
    if(!item || !ctxNode) return;
    var act = item.dataset.act, oid = ctxNode.oid || '';
    this.classList.add('hidden');
    if(act === 'walk'){ $('oid').value = oid; runProbe('WALK', oid); }
    else if(act === 'get'){
      var g = (ctxNode.kind === 'scalar') ? oid + '.0' : oid;
      $('oid').value = g; runProbe('GET', g);
    }
    else if(act === 'next'){ $('oid').value = oid; runProbe('GETNEXT', oid); }
    else if(act === 'set'){
      if(ctxNode.__synthetic){ toast('请对具体的标量/列节点执行 SET', true); return; }
      openSetDialog((ctxNode.kind === 'scalar') ? oid + '.0' : oid);
    }
    else if(act === 'table'){ $('oid').value = oid; setView('smart'); runProbe('WALK', oid); }
    else if(act === 'copyOid'){ copyText(oid); }
    else if(act === 'copyName'){ copyText(ctxNode.name); }
  });
  document.addEventListener('click', function(){ $('contextMenu').classList.add('hidden'); });

  var dragging = false;
  $('splitter').addEventListener('mousedown', function(e){
    dragging = true; this.classList.add('dragging'); e.preventDefault();
  });
  document.addEventListener('mousemove', function(e){
    if(!dragging) return;
    var w = Math.max(220, Math.min(window.innerWidth * 0.7, e.clientX));
    $('treePane').style.width = w + 'px';
  });
  document.addEventListener('mouseup', function(){
    if(dragging){ dragging = false; $('splitter').classList.remove('dragging'); }
  });

  loadCaps();
  loadMibs();
})();
