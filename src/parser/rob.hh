#pragma once

/*
 * A simplified version of
 * http://bloglitb.blogspot.com/2010/07/access-to-private-members-thats-easy.html
 */

template<typename Victim, typename FieldType, FieldType Victim::*p>
struct rob {
  static FieldType Victim::*ptr() { return p; }
};

