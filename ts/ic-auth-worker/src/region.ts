/**
 * Routes callers to nine named regional instances plus a shared default.
 * Names form a fixed set, so arbitrary caller input cannot create unbounded
 * container instances. A Durable Object location hint is best effort and is
 * only applied at initial creation; it is not a placement guarantee.
 *
 * Service-binding callers can pass their incoming request.cf.colo in
 * x-edge-name. For direct requests, cf.colo and cf.continent are fallbacks.
 */
export const EDGE_NAME_HEADER = 'x-edge-name'

export interface AuthInstance {
	/** Durable Object name — one container per distinct value. */
	name: string
	/** Preferred region; best effort and used only on initial creation. */
	locationHint?: DurableObjectLocationHint
}

/**
 * The instance every unlocated caller shares: a caller that passed no
 * location, `wrangler dev`, and any colo this table has not heard of.
 * Deliberately unpinned — with no hint it is created near its first caller,
 * which is the best inference available.
 */
const DEFAULT_INSTANCE: AuthInstance = { name: 'default' }

/**
 * Colo → the preferred region for its instance, grouped by region so the table
 * stays readable. Generated from Cloudflare's own published colo list:
 *
 *     curl -s -H 'Referer: https://speed.cloudflare.com/' \
 *       https://speed.cloudflare.com/locations
 *
 * Each entry's `region` maps onto a location hint one-for-one, except that
 * North America is split at 104°W into wnam/enam and Europe at 19°E into
 * weur/eeur — these are application routing heuristics, not Cloudflare boundaries.
 * Regenerate when Cloudflare opens colos that carry real traffic; until then a
 * colo missing from the table is merely unlocated, never an error.
 */
const COLOS_BY_REGION = {
	wnam: 'ABQ ANC DEN HNL LAS LAX PDX PHX SAN SEA SFO SJC SLC SMF YVR YXE YYC',
	enam:
		'ATL AUS BGI BGR BNA BOS BUF CLE CLT CMH CVG DFW DTW EWR FSD ' +
		'GDL GUA IAD IAH IND JAX KIN MCI MEM MEX MIA MSP OKC OMA ORD ' +
		'ORF PHL PIT QRO RDU RIC SAT SDQ SJU STI STL TLH TPA YHZ YUL ' +
		'YWG YYZ',
	sam:
		'ARI ARU ASU BAQ BEL BOG BSB CAW CFC CGB CLO CNF COR CWB EZE ' +
		'FLN FOR GEO GIG GND GRU GYE GYN JDO JOI LIM LPB MAO MDE NQN ' +
		'NVT PBM PMW POA POS PTY QWJ RAO REC SAP SCL SJK SJO SJP SOD ' +
		'SSA TGU UDI UIO VCP VIX XAP',
	weur:
		'AMS ARN BCN BOD BRU BTS CDG CPH DUB DUS FCO FRA GOT GVA HAM ' +
		'KEF LHR LIS LJU LUX LYS MAD MAN MLA MRS MUC MXP OSL PMO PRG ' +
		'STR TXL VIE WRO ZAG ZRH',
	eeur:
		'ADB AKX ALA ATH BEG BUD DME HEL IST KBP LCA LED MSQ OTP RIX ' +
		'SKG SKP SOF TBS TIA TLL VNO WAW',
	apac:
		'AGR AIP AMD BBI BDQ BKK BLR BOM BWN CCU CEB CGK CGP CGY CJB ' +
		'CMB CNN CNX COK CRK DAC DAD DEL DPS FRU FUK GUM HAN HKG HYD ' +
		'ICN ISB IXC JHB JOG JRG KCH KHH KHI KIX KJA KNU KTM KUL LHE ' +
		'MAA MFM MLE MLG MNL NAG NQZ NRT OKA PAT PBH PNH PNQ SGN SIN ' +
		'TPE UDR ULN URT VTE',
	oc: 'ADL AKL BNE CBR CHC HBA MEL NOU PER PPT SUV SYD WLG',
	afr:
		'AAE ABJ ACC ADD ALG ASK CAI CPT CZL DAR DKR DLA DUR EBB FIH ' +
		'GBE HRE JIB JNB KGL LAD LLW LOS LUN MBA MPM MRU NBO ORN OUA ' +
		'RUN TNR TUN WDH',
	me:
		'AMM BAH BEY BGW BSR DMM DOH DXB EBL EVN GYD HFA ISU JED KWI ' +
		'LLK MCT NJF RUH TLV XNH ZDM'
} satisfies Partial<Record<DurableObjectLocationHint, string>>

/**
 * A Map, not an object literal: an untrusted lookup key like `constructor`
 * finds a truthy inherited member on a plain object and would route to a
 * garbage instance.
 */
const REGION_BY_COLO = new Map<string, DurableObjectLocationHint>(
	Object.entries(COLOS_BY_REGION).flatMap(([region, colos]) =>
		colos
			.split(' ')
			.map((colo) => [colo, region as DurableObjectLocationHint] as const)
	)
)

/**
 * Continent → region, for a request that reached an edge directly and carries
 * a `cf` whose colo the table above has not heard of. Coarser than the colo
 * lookup by construction — a continent cannot tell wnam from enam, and the
 * region picked is the populated half. 'AN' (Antarctica) is deliberately
 * absent and falls through to the default.
 */
const REGION_BY_CONTINENT = new Map<string, DurableObjectLocationHint>([
	['AF', 'afr'],
	['AS', 'apac'],
	['EU', 'weur'],
	['NA', 'enam'],
	['OC', 'oc'],
	['SA', 'sam']
])

export function instanceFor(req: Request): AuthInstance {
	const cf = req.cf as { colo?: unknown; continent?: unknown } | undefined

	// The header first: over a service binding it is the only signal there is,
	// and it names the colo the *user* reached, which is the location worth
	// serving. `cf.colo` — our own edge — is the fallback for traffic that
	// arrives here directly.
	const told = req.headers.get(EDGE_NAME_HEADER)
	const colo = told || (typeof cf?.colo === 'string' ? cf.colo : '')
	if (colo) {
		const region = REGION_BY_COLO.get(colo.toUpperCase())
		if (region) return { name: region, locationHint: region }
	}

	const continent = cf?.continent
	if (typeof continent === 'string') {
		const region = REGION_BY_CONTINENT.get(continent.toUpperCase())
		if (region) return { name: region, locationHint: region }
	}

	return DEFAULT_INSTANCE
}
