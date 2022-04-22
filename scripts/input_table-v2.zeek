module MyEnrichment;

type Idx: record {
        ip: addr;
};

type Val: record {
        device_type: string	&log;
        role: string	&log;
        user: string	&log;
        city_location: string	&log;
        building: string	&log;
        floor_room: string	&log;
};

global enrichment_table: table[addr] of Val = table();

event zeek_init() {
    Input::add_table([
		$source="enrichment.csv", $name="enrichment_table",
		$idx=Idx, $val=Val, $destination=enrichment_table,
		$mode=Input::REREAD
	]);
}
