const char *fallbackShader_fogpass_fp =
"uniform vec4  u_Color;\n"
"\n"
"varying float var_Scale;\n"
"\n"
"void main()\n"
"{\n"
"\tgl_FragColor = u_Color;\n"
"\tgl_FragColor.a = sqrt(clamp(var_Scale, 0.0, 1.0));\n"
"}\n"
;
