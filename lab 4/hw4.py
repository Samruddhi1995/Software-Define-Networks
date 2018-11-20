from mininet.topo import Topo

class MyTopo( Topo ):
    "Simple topology example."

    def __init__( self ):
        "Create custom topo."

        # Initialize topology
        Topo.__init__( self )

        # Add hosts and switches
        Host1 = self.addHost( 'h1' )
        Host2 = self.addHost( 'h2' )
	Host3 = self.addHost( 'h3' )
	Host4 = self.addHost( 'h4' )
        A = self.addSwitch( 's1' )
        B = self.addSwitch( 's2' )
	C = self.addSwitch( 's3' )
	D = self.addSwitch( 's4' )
	
        # Add links
        self.addLink( Host1, A, 1, 1  )
        self.addLink( Host2,B, 1, 1 )
	self.addLink( Host3,C, 1, 1 )
	self.addLink( Host4,D, 1, 1)
	self.addLink( A,B, 2 , 2 )
	self.addLink( A,D, 3, 2 )
	self.addLink( B,C, 3, 2 )
	self.addLink( C,D, 3, 3 )

topos = { 'mytopo': ( lambda: MyTopo() ) }



