#
/^CREATE EXTENSION/c\
SET client_min_messages = warning;\
\\set ECHO none\
\\i ip4r.sql\
\\set ECHO all\
RESET client_min_messages;
