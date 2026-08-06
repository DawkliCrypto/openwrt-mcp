// Hello-world probe for the GL.iNet web UI.
//
// Purpose: find out whether a third-party view loads at all, before investing in a real one.
//
// The SPA's router does, per /www/js/app.*.js:
//
//     axios.get(`/views/gl-sdk4-ui-${view}.common.js?_t=...`)
//          .then(res => { const component = eval(res.data)
//                         to.matched[index].components.default = component
//                         next() })
//
// So the file is fetched as text, eval'd, and whatever the eval *evaluates to* becomes the
// route's component. That is a far looser contract than the shipped bundles imply: they are
// webpack `libraryTarget: commonjs2` output beginning `module.exports=...`, which works only
// because a direct eval inherits the enclosing webpack wrapper's scope, where `module` is a
// real binding. An assignment expression evaluates to the assigned value, so eval returns the
// component either way.
//
// Nothing here needs webpack. An IIFE returning a plain Vue 2 options object satisfies the
// contract directly, and assigning module.exports inside a try/catch keeps it working whether
// or not `module` happens to be in scope -- the return value is what the loader uses.
//
// Vue is 2.6.12 on this firmware, so a render function is the dependency-free way to produce
// markup: vue-loader templates would need a compiler that is not available at eval time.
(function () {
  var component = {
    name: 'openwrt-mcp-hello',

    data: function () {
      return { probe: 'openwrt-mcp view loaded' };
    },

    render: function (h) {
      return h('div', { style: { padding: '24px', fontFamily: 'monospace' } }, [
        h('h2', 'openwrt-mcp'),
        h('p', this.probe),
        h('p', { style: { color: '#888' } },
          'If you can read this, a third-party view loads and Phase 2 is viable.')
      ]);
    }
  };

  try { module.exports = component; } catch (e) { /* not in a CommonJS scope; the return value is what counts */ }
  return component;
})()
