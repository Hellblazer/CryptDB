#!/usr/bin/perl

use DBIx::MyParsePP;
use Data::Dumper;

my $parser = DBIx::MyParsePP->new();

# my $query = $parser->parse("SELECT * FROM t WHERE x=5");
my $query = $parser->parse("UPDATE t SET v=5 WHERE x=7");

print Dumper $query;
print $query->toString();

