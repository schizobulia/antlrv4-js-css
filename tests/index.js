const antlrv4_js_css = require('../dist/index-umd')

class Visitor extends antlrv4_js_css.Visitor {
  visitTerminal(node) {
    let text = node.getText()
    console.log(text)
  }
}

antlrv4_js_css.transform('.b { color: red; }', new Visitor())