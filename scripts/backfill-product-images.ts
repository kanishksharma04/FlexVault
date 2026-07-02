import { db } from "./lib/db";
import { PRODUCT_IMAGE_OVERRIDES } from "../src/lib/product-images";


async function main() {
  const products = await db.product.findMany({ select: { id: true, name: true } });

  let updated = 0;
  const unmatched: string[] = [];

  for (const product of products) {
    const images = PRODUCT_IMAGE_OVERRIDES[product.name];
    if (!images) {
      unmatched.push(product.name);
      continue;
    }
    await db.product.update({ where: { id: product.id }, data: { images } });
    updated++;
  }

  console.log(`Updated ${updated}/${products.length} products with sourced photography.`);
  if (unmatched.length > 0) {
    console.log(`No sourced image for ${unmatched.length} product(s), left on placeholder:`);
    for (const name of unmatched) console.log(`  - ${name}`);
  }
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await db.$disconnect();
  });
