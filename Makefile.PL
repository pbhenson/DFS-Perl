use ExtUtils::MakeMaker;


WriteMakefile(
    'NAME'	=> 'DCE::DFS',
    'VERSION_FROM' => 'DFS.pm',
    'LIBS'	=> ['-ldce /opt/dce/usr/lib/libdcedfs.so.1'], 
    'DEFINE'    => '-D_REENTRANT',
    'OBJECT'    => '$(BASEEXT)$(OBJ_EXT)'
);
