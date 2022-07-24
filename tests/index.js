const antlrv4_js_css = require('../lib/css')

class Visitor extends antlrv4_js_css.Visitor {
  visitTerminal(node) {
    let text = node.getText()
    console.log(text)
  }
}

class ErrorListener extends antlrv4_js_css.ErrorListener {
  syntaxError(recognizer, offendingSymbol, line, column, msg, e) {
    console.log(`${line}:${column}: ${msg}`)
  }
}

class ErrorHandler extends antlrv4_js_css.DefaultErrorStrategy {
  reportError(recognizer, e) {
  }
  reportUnwantedToken(recognizer) {
  }
  reportMissingToken(recognizer) {
  }
}

antlrv4_js_css.transform(`.b { color: red;`, new Visitor(), new ErrorListener(), new ErrorHandler())
