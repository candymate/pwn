const importObject = {
  js: {
    a: function(arg) {
      console.log(arg);
    },
    b: new WebAssembly.Memory({initial:10, maximum:100}),
    c: new WebAssembly.Table({initial:2, element:"anyfunc"}),
    d: new WebAssembly.Global({value:'i32', mutable:true}, 0)
  }
};
const wasm_code = new Uint8Array([CODE]);
const wasm_mod = new WebAssembly.Module(wasm_code);
const wasm_instance = new WebAssembly.Instance(wasm_mod, importObject);
const f = wasm_instance.exports.main;

f();

// while(1);