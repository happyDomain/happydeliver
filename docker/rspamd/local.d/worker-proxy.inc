# Enable rspamd milter proxy worker via Unix socket for Postfix integration
bind_socket = "/var/spool/postfix/rspamd/rspamd-milter.sock mode=0660 owner=rspamd group=mail";
upstream "local" {
  default = yes;
  self_scan = yes;
}
