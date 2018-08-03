use ExtUtils::MakeMaker;


WriteMakefile(
    'NAME'	=> 'DCE::DFS',
    'VERSION_FROM' => 'DFS.pm',
    'LIBS'	=> ['-ldce'], 
    'DEFINE'    => '-I/usr/include/dce -D_REENTRANT',
    'OBJECT'    => '$(BASEEXT)$(OBJ_EXT) /usr/local/lib/libdcedfs.a'
);
