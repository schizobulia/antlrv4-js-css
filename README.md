# antlrv4-js-css

## 使用antlrv4的js api 解析css

### 下载
```bash
$ npm i antlrv4-js-css
```
### 快速开始

```javascript
const antlrv4_js_css = require('antlrv4-js-css')

class Visitor extends antlrv4_js_css.Visitor {
  visitTerminal(node) {
    let text = node.getText()
    console.log(text)
  }
}

antlrv4_js_css.transform('.b { color: red; }', new Visitor())
```

### 浏览器中使用

```html
<script src="../dist/index-umd.js"></script>
<script>
  console.log(antlrv4_js_css)
</script>
```

### 其他模块的支持

- [v] es
- [v] esm
- [v] umd

### API
```javascript
// Visit a parse tree produced by CssParser#stylesheet.
visitStylesheet(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#goodCharset.
visitGoodCharset(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#badCharset.
visitBadCharset(ctx) {
    return this.visitChildren(ctx);
}

// @import('xxx.css')
visitGoodImport(ctx) {
    return this.visitChildren(ctx);
}

// @import('xxx.css')
visitBadImport(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#goodNamespace.
visitGoodNamespace(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#badNamespace.
visitBadNamespace(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#namespacePrefix.
visitNamespacePrefix(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#media.
visitMedia(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#mediaQueryList.
visitMediaQueryList(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#mediaQuery.
visitMediaQuery(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#mediaType.
visitMediaType(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#mediaExpression.
visitMediaExpression(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#mediaFeature.
visitMediaFeature(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#page.
visitPage(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#pseudoPage.
visitPseudoPage(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#selectorGroup.
visitSelectorGroup(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#selector.
visitSelector(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#combinator.
visitCombinator(ctx) {
    return this.visitChildren(ctx);
}

// .a .b { } 获取 .a and .b
visitSimpleSelectorSequence(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#typeSelector.
visitTypeSelector(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#typeNamespacePrefix.
visitTypeNamespacePrefix(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#elementName.
visitElementName(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#universal.
visitUniversal(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#className.
visitClassName(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#attrib.
visitAttrib(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#pseudo.
visitPseudo(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#functionalPseudo.
visitFunctionalPseudo(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#expression.
visitExpression(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#negation.
visitNegation(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#negationArg.
visitNegationArg(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#goodOperator.
visitGoodOperator(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#badOperator.
visitBadOperator(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#goodProperty.
visitGoodProperty(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#badProperty.
visitBadProperty(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#knownRuleset.
visitKnownRuleset(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#unknownRuleset.
visitUnknownRuleset(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#declarationList.
visitDeclarationList(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#knownDeclaration.
visitKnownDeclaration(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#unknownDeclaration.
visitUnknownDeclaration(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#prio.
visitPrio(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#value.
visitValue(ctx) {
    return this.visitChildren(ctx);
}

// { color: red; } ctx.getText() 获取 'red'
visitExpr(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#knownTerm.
visitKnownTerm(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#unknownTerm.
visitUnknownTerm(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#badTerm.
visitBadTerm(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#function_.
visitFunction_(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#dxImageTransform.
visitDxImageTransform(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#hexcolor.
visitHexcolor(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#number.
visitNumber(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#percentage.
visitPercentage(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#dimension.
visitDimension(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#unknownDimension.
visitUnknownDimension(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#any_.
visitAny_(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#unknownAtRule.
visitUnknownAtRule(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#atKeyword.
visitAtKeyword(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#unused.
visitUnused(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#block.
visitBlock(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#nestedStatement.
visitNestedStatement(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#groupRuleBody.
visitGroupRuleBody(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#supportsRule.
visitSupportsRule(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#supportsCondition.
visitSupportsCondition(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#supportsConditionInParens.
visitSupportsConditionInParens(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#supportsNegation.
visitSupportsNegation(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#supportsConjunction.
visitSupportsConjunction(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#supportsDisjunction.
visitSupportsDisjunction(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#supportsDeclarationCondition.
visitSupportsDeclarationCondition(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#generalEnclosed.
visitGeneralEnclosed(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#var_.
visitVar_(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#calc.
visitCalc(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#calcSum.
visitCalcSum(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#calcProduct.
visitCalcProduct(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#calcValue.
visitCalcValue(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#fontFaceRule.
visitFontFaceRule(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#knownFontFaceDeclaration.
visitKnownFontFaceDeclaration(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#unknownFontFaceDeclaration.
visitUnknownFontFaceDeclaration(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#keyframesRule.
visitKeyframesRule(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#keyframesBlocks.
visitKeyframesBlocks(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#keyframeSelector.
visitKeyframeSelector(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#viewport.
visitViewport(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#counterStyle.
visitCounterStyle(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#fontFeatureValuesRule.
visitFontFeatureValuesRule(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#fontFamilyNameList.
visitFontFamilyNameList(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#fontFamilyName.
visitFontFamilyName(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#featureValueBlock.
visitFeatureValueBlock(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#featureType.
visitFeatureType(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#featureValueDefinition.
visitFeatureValueDefinition(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#ident.
visitIdent(ctx) {
    return this.visitChildren(ctx);
}

// Visit a parse tree produced by CssParser#ws.
visitWs(ctx) {
    return this.visitChildren(ctx);
}
```

### 错误处理API
```javascript
const antlrv4_js_css = require('antlrv4-js-css')

class Visitor extends antlrv4_js_css.Visitor {
}

class ErrorListener extends antlrv4_js_css.ErrorListener {
  syntaxError(recognizer, offendingSymbol, line, column, msg, e) {

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
antlrv4_js_css.transform('.b { color: red;', new Visitor(), new ErrorListener(), new ErrorHandler())
```

### 其他库
- [css3](https://github.com/schizobulia/antlrv4-js-css)
- [xml](https://github.com/schizobulia/antlrv4-js-xml)
- [html](https://github.com/schizobulia/antlrv4-js-html)


### API参考
- [antlr4](https://github.com/antlr/antlr4/blob/master/doc/index.md)