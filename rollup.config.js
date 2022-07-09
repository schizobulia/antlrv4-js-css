import commonjs from 'rollup-plugin-commonjs'
import { nodeResolve } from '@rollup/plugin-node-resolve';
import nodePolyfills from 'rollup-plugin-node-polyfills';
import { terser } from "rollup-plugin-terser";

const plugins = [
  commonjs(),
  nodePolyfills(),
  nodeResolve({ preferBuiltins: false }),
  terser()
]

export default [
  {
    input: 'index.js',
    output: {
      file: 'dist/index-es.js',
      format: 'es'
    },
    plugins: plugins
  },
  {
    input: 'index.js',
    output: {
      file: 'dist/index-esm.js',
      format: 'esm'
    },
    plugins: plugins
  },
  {
    input: 'index.js',
    output: {
      file: 'dist/index-umd.js',
      format: 'umd',
      name: 'antlrv4_js_css'
    },
    plugins: plugins
  },
]