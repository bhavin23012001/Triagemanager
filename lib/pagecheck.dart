import 'package:flutter/material.dart';
import 'package:webview_flutter/webview_flutter.dart';
import 'main.dart' show card, muted, amber, teal;

const _hook = r"""
(function(){if(window.__tri)return;window.__tri=1;
function s(m){try{Err.postMessage(String(m))}catch(e){}}
window.addEventListener('error',function(e){
if(e.target&&e.target!==window){s('Resource failed: '+(e.target.src||e.target.href||e.target.tagName));}
else{s('JS error: '+e.message+' ('+(e.filename||'')+':'+e.lineno+')');}},true);
window.addEventListener('unhandledrejection',function(e){s('Unhandled promise rejection: '+(e.reason&&e.reason.message||e.reason));});
document.addEventListener('securitypolicyviolation',function(e){s('CSP blocked '+e.blockedURI+' ('+e.violatedDirective+')');});
var ce=console.error;console.error=function(){s('console.error: '+Array.prototype.slice.call(arguments).join(' '));ce.apply(console,arguments);};
var of=window.fetch;
if(of){window.fetch=function(){var a=arguments;var u=(a[0]&&a[0].url)||a[0];
return of.apply(this,a).then(function(r){if(!r.ok){s('API call failed: '+r.status+' '+u);}return r;},function(e){s('API call error: '+u+' ('+e+')');throw e;});};}
var ox=XMLHttpRequest.prototype.open;
XMLHttpRequest.prototype.open=function(m,u){this.addEventListener('loadend',function(){if(this.status===0||this.status>=400){s('API call failed: '+this.status+' '+u);}});return ox.apply(this,arguments);};
})();
""";

class PageCheckScreen extends StatefulWidget {
  const PageCheckScreen({super.key, required this.url});
  final String url;
  @override
  State<PageCheckScreen> createState() => _PageCheckScreenState();
}

class _PageCheckScreenState extends State<PageCheckScreen> {
  late final WebViewController c;
  final events = <String>[];
  bool done = false;

  void _add(String m) {
    if (!mounted || events.contains(m)) return;
    setState(() => events.add(m));
  }

  @override
  void initState() {
    super.initState();
    c = WebViewController()
      ..setJavaScriptMode(JavaScriptMode.unrestricted)
      ..addJavaScriptChannel('Err', onMessageReceived: (m) => _add(m.message))
      ..setNavigationDelegate(NavigationDelegate(
        onPageStarted: (_) => c.runJavaScript(_hook),
        onPageFinished: (_) async {
          await Future.delayed(const Duration(seconds: 2));
          try {
            final r = await c.runJavaScriptReturningResult(
                '(document.body ? document.body.innerText.trim().length : -1)');
            final n = int.tryParse(r.toString().replaceAll('"', '')) ?? -1;
            if (n >= 0 && n < 20) _add('Page looks blank: almost no visible text was rendered');
          } catch (_) {}
          if (mounted) setState(() => done = true);
        },
        onWebResourceError: (e) => _add(
            'Load error: ${e.description}${e.isForMainFrame == true ? ' (main page)' : ''}'),
        onHttpError: (e) => _add('HTTP ${e.response?.statusCode} for ${e.request?.uri}'),
      ))
      ..loadRequest(Uri.parse(widget.url));
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Page check')),
      body: Column(children: [
        SizedBox(height: 260, child: WebViewWidget(controller: c)),
        Padding(
          padding: const EdgeInsets.all(16),
          child: Row(children: [
            Text(done ? 'LOADED' : 'LOADING...',
                style: TextStyle(color: done ? teal : amber, fontSize: 12, fontWeight: FontWeight.w600)),
            const SizedBox(width: 8),
            Text('${events.length} issue(s)', style: const TextStyle(color: muted, fontSize: 12)),
          ]),
        ),
        Expanded(
          child: events.isEmpty
              ? Padding(
                  padding: const EdgeInsets.all(16),
                  child: Text(
                    done
                        ? 'No JavaScript errors or failed resources seen during load. Errors thrown before this app attached its listener can be missed.'
                        : 'Waiting for the page...',
                    style: const TextStyle(color: muted)),
                )
              : ListView(padding: const EdgeInsets.symmetric(horizontal: 16), children: [
                  for (final e in events)
                    Container(
                      margin: const EdgeInsets.only(bottom: 8),
                      padding: const EdgeInsets.all(12),
                      decoration: BoxDecoration(color: card, borderRadius: BorderRadius.circular(12)),
                      child: Text(e, style: const TextStyle(fontFamily: 'monospace', fontSize: 12)),
                    ),
                ]),
        ),
      ]),
    );
  }
}
