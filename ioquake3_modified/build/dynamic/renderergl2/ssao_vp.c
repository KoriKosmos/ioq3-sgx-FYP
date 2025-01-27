const char *fallbackShader_ssao_vp =
"attribute vec4 attr_Position;\n"
"attribute vec4 attr_TexCoord0;\n"
"\n"
"varying vec2   var_ScreenTex;\n"
"\n"
"void main()\n"
"{\n"
"\tgl_Position = attr_Position;\n"
"\tvar_ScreenTex = attr_TexCoord0.xy;\n"
"\t//vec2 screenCoords = gl_Position.xy / gl_Position.w;\n"
"\t//var_ScreenTex = screenCoords * 0.5 + 0.5;\n"
"}\n"
;
