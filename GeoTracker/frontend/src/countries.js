import {feature} from "topojson-client";
import world from "world-atlas/countries-110m.json";
import countries from "i18n-iso-countries";
// Unmapped disputed territories stay visible but cannot trigger a country rule.
export const countryFeatures=feature(world,world.objects.countries).features.map(f=>({
 feature:f,code:countries.numericToAlpha2(String(f.id).padStart(3,"0"))||null,name:f.properties?.name||"Unknown region"
}));
export const featureByCode=new Map(countryFeatures.filter(c=>c.code).map(c=>[c.code,c.feature]));
