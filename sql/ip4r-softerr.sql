-- Tests for pg16+

--valid and invalid ip4
select v.i, v.t, pg_input_is_valid(v.t,'ip4') as valid, ierr.*
  from (values (1, '1.2.3.4'),
	       (2, '0.0.0.0'),
	       (3, '255.255.255.255'),
	       -- invalid
	       (4, '1.2.3'),
	       (5, '0'),
	       (6, ' 1.2.3.4'),
	       (7, '1.2.3.4 '),
	       (8, '0.0.0.256'),
	       (9 , '0.0.256'),
	       (10, '0..255.0'),
	       (11, '+0.255.0.0'),
	       (12, '1.2.3.4-1.2.3.4')) v(i,t)
  left join lateral (select * from pg_input_error_info(v.t,'ip4')) ierr
		 on true;

--valid and invalid ip4r
select v.i, v.t, pg_input_is_valid(v.t,'ip4r') as valid, ierr.*
  from (values (1, '1.2.3.4'),
	       (2, '255.255.255.255/32'),
	       (3, '128.0.0.0/1'),
	       (4, '0.0.0.0/0'),
	       (5, '1.2.3.4-5.6.7.8'),
	       (6, '5.6.7.8-1.2.3.4'),
	       -- invalid
	       (7, '1.2.3'),
	       (8, '255.255.255.255.255.255.255.255.255'),
	       (9, '255.255.255.255.255-255.255.255.255.255'),
	       (10, '255.255.255.255-1.2.3.4.5'),
	       (11, '0.0.0.1/31'),
	       (12, '128.0.0.0/0'),
	       (13, '0.0.0.0/33'),
	       (14, '0.0.0.0/3.0'),
	       (15, '0.0.0.0/+33')
	       ) v(i,t)
  left join lateral (select * from pg_input_error_info(v.t,'ip4r')) ierr
		 on true;

--valid and invalid ip6

select v.i, v.t, pg_input_is_valid(v.t,'ip6') as valid, ierr.*
  from (values (1, '0000:0000:0000:0000:0000:0000:0000:0000'),
	       (2, '0000:0000:0000:0000:0000:0000:0000:0001'),
	       (3, '0:0:0:0:0:0:0:0'),
	       (4, '0:0:0:0:0:0:0:1'),
	       (5, '0:0:0:0:0:0:13.1.68.3'),
	       (6, '0:0:0:0:0:FFFF:129.144.52.38'),
	       (7, '0::0'),
	       (8, '1:2:3:4:5:6:1.2.3.4'),
	       -- invalid
	       (9, ''),
	       (10, '02001:0000:1234:0000:0000:C1C0:ABCD:0876'),
	       (11, '1.2.3.4:1111:2222:3333:4444::5555'),
	       (12, '123'),
	       (13, '12345::6:7:8'),
	       (14, '::1.2.256.4'),
	       (15, 'FF01::101::2'),
	       (16, 'FF02:0000:0000:0000:0000:0000:0000:0000:0001'),
	       (17, 'ldkfj')
       ) v(i,t)
  left join lateral (select * from pg_input_error_info(v.t,'ip6')) ierr
		 on true;

--valid and invalid ip6r

select v.i, v.t, pg_input_is_valid(v.t,'ip6r') as valid, ierr.*
  from (values (1, '::'),
	       (2, 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'),
	       (3, '1::2'),
	       (4, '::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'),
	       (5, 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff-::'),
	       (6, '1::2-3::4'),
	       (7, '3::4-3::4'),
	       (8, '3::4-1::2'),
	       -- invalid
	       (9, '::-::-::'),
	       (10, 'ffff:ffff:ffff:ffff:ffff:ffff:ffff-ffff'),
	       (11, '::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'),
	       (12, 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff-::'),
	       (13, 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128'),
	       (14, '0000:0000:0000:0000:0000:0000:0000:0001/127'),
	       (15, '0800:0000:0000:0000:0000:0000:0000:0000/4'),
	       (16, '8000:0000:0000:0000:0000:0000:0000:0000/0'),
	       (17, '::/129'),
	       (18, '::/255'),
	       (19, '::/256'),
	       (20, '::/+0'),
	       (21, '::/0-0'),
	       (22, '::-::/0')
       ) v(i,t)
  left join lateral (select * from pg_input_error_info(v.t,'ip6r')) ierr
		 on true;

--valid and invalid ipaddress

select v.i, v.t, pg_input_is_valid(v.t,'ipaddress') as valid, ierr.*
  from (values (1, '1.2.3.4'),
	       (2, '0.0.0.0'),
	       (3, '255.255.255.255'),
	       (4, '1::8'),
	       (5, '2001:0000:1234:0000:0000:C1C0:ABCD:0876'),
	       (6, '2001:0db8:0000:0000:0000:0000:1428:57ab'),
	       -- invalid
	       (7, '1.2.3'),
	       (8, '0'),
	       (9, ' 1.2.3.4'),
	       (10, '1.2.3.4 '),
	       (11, '0.0.0.256'),
	       (12, ''),
	       (13, '02001:0000:1234:0000:0000:C1C0:ABCD:0876'),
	       (14, '1.2.3.4:1111:2222:3333:4444::5555'),
	       (15, '::ffff:2.3.4'),
	       (16, '::ffff:257.1.2.3'),
	       (17, 'FF01::101::2'),
	       (18, 'FF02:0000:0000:0000:0000:0000:0000:0000:0001'),
	       (19, 'ldkfj')
       ) v(i,t)
  left join lateral (select * from pg_input_error_info(v.t,'ipaddress')) ierr
		 on true;

--valid and invalid iprange

select v.i, v.t, pg_input_is_valid(v.t,'iprange') as valid, ierr.*
  from (values (1, '-'),
	       (2, '1.2.3.4'),
	       (3, '255.255.255.255/32'),
	       (4, '128.0.0.0/1'),
	       (5, '0.0.0.0/0'),
	       (6, '1.2.3.4-5.6.7.8'),
	       (7, '5.6.7.8-1.2.3.4'),
	       (8, '1.2.3.4-1.2.3.4'),
	       (9, '::'),
	       (10, '1::2'),
	       (11, '::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'),
	       (12, 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff-::'),
	       (13, '1::2-3::4'),
	       (14, '3::4-3::4'),
	       (15, '3::4-1::2'),
	       (16, 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128'),
	       (17, 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe/127'),
	       (18, '8000:0000:0000:0000:0000:0000:0000:0000/1'),
	       (19, '0000:0000:0000:0000:0000:0000:0000:0000/0'),
	       -- invalid
	       (20, '1.2.3'),
	       (21, '255.255.255.255.255.255.255.255.255'),
	       (22, '255.255.255.255.255-255.255.255.255.255'),
	       (23, '255.255.255.255-1.2.3.4.5'),
	       (24, '255.255.255.255-1.2.3'),
	       (25, '0.0.0.1/31'),
	       (26, '64.0.0.0/1'),
	       (27, '128.0.0.0/0'),
	       (28, '0.0.0.0/33'),
	       (29, '0.0.0.0/3.0'),
	       (30, '0.0.0.0/+33'),
	       (31, '::-::-::'),
	       (32, 'ffff:ffff:ffff:ffff:ffff:ffff:ffff-ffff'),
	       (33, '::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'),
	       (34, 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff-::'),
	       (35, 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128'),
	       (36, '0000:0000:0000:0000:0000:0000:0000:0001/127'),
	       (37, '0800:0000:0000:0000:0000:0000:0000:0000/4'),
	       (38, '8000:0000:0000:0000:0000:0000:0000:0000/0'),
	       (39, '::/129'),
	       (40, '::/255'),
	       (41, '::/256'),
	       (42, '::/+0'),
	       (43, '::/0-0'),
	       (44, '::-::/0'),
	       (45, '-::'),
	       (46, '-1.2.3.4'),
	       (47, '1.2.3.4-')
       ) v(i,t)
  left join lateral (select * from pg_input_error_info(v.t,'iprange')) ierr
		 on true;

-- end
