use ExtUtils::MakeMaker;


WriteMakefile(
    'NAME'	=> 'DCE::DFS',
    'VERSION_FROM' => 'DFS.pm',
    'LIBS'	=> ['-ldce'], 
    'OBJECT'    => '$(BASEEXT)$(OBJ_EXT) /usr/local/lib/libdcedfs.a'
);
