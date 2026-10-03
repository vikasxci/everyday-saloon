const cloudinary = require('cloudinary').v2;

const SaloonStaff             = require('../models/SaloonStaff');
const SaloonService           = require('../models/SaloonService');
const SaloonWorkEntry         = require('../models/SaloonWorkEntry');
const SaloonCustomer          = require('../models/SaloonCustomer');
const SaloonAttendance        = require('../models/SaloonAttendance');
const SaloonSalarySettlement  = require('../models/SaloonSalarySettlement');
const SaloonCollectionRequest = require('../models/SaloonCollectionRequest');
const BusinessActivityLog     = require('../models/BusinessActivityLog');
const SaloonBusiness          = require('../models/SaloonBusiness');
const Counter                 = require('../models/Counter');

// "https://res.cloudinary.com/<cloud>/image/upload/v1712/folder/name.jpg" → "folder/name"
function publicIdFromUrl(url) {
  if (!url || !/res\.cloudinary\.com/.test(url)) return null;
  const m = /\/upload\/(?:[^/]+\/)*?v\d+\/(.+)\.[a-z0-9]+$/i.exec(url) || /\/upload\/(.+)\.[a-z0-9]+$/i.exec(url);
  return m ? m[1] : null;
}

// Permanently removes a saloon and everything under it, including its uploaded
// photos. Activity logs go too; the caller writes one deletion record afterwards.
async function deleteSaloonData(saloon) {
  const id = saloon._id;

  const [staffPics, customers, billPics] = await Promise.all([
    SaloonStaff.find({ saloon: id, avatar: { $ne: null } }).select('avatar').lean(),
    SaloonCustomer.find({ saloon: id }).select('avatar photos.url').lean(),
    SaloonWorkEntry.find({ saloon: id, customerPhoto: { $ne: null } }).select('customerPhoto').lean()
  ]);
  const urls = [
    saloon.logo, saloon.coverImage,
    ...staffPics.map(s => s.avatar),
    ...customers.flatMap(c => [c.avatar, ...(c.photos || []).map(p => p.url)]),
    ...billPics.map(b => b.customerPhoto)
  ];
  const publicIds = [...new Set(urls.map(publicIdFromUrl).filter(Boolean))];

  const [staff, services, entries, custs, attendance, settlements, requests] = await Promise.all([
    SaloonStaff.deleteMany({ saloon: id }),
    SaloonService.deleteMany({ saloon: id }),
    SaloonWorkEntry.deleteMany({ saloon: id }),
    SaloonCustomer.deleteMany({ saloon: id }),
    SaloonAttendance.deleteMany({ saloon: id }),
    SaloonSalarySettlement.deleteMany({ saloon: id }),
    SaloonCollectionRequest.deleteMany({ saloon: id })
  ]);
  await BusinessActivityLog.deleteMany({ business: id });
  await Counter.deleteMany({ key: `bill:${id}` });
  await SaloonBusiness.findByIdAndDelete(id);

  // Best effort: a failed image delete must not undo the account deletion
  if (publicIds.length && process.env.CLOUDINARY_API_SECRET) {
    for (let i = 0; i < publicIds.length; i += 100) {
      cloudinary.api.delete_resources(publicIds.slice(i, i + 100))
        .catch(err => console.warn('⚠️  Cloudinary cleanup failed:', err.message));
    }
  }

  return {
    staff: staff.deletedCount, services: services.deletedCount,
    bills: entries.deletedCount, customers: custs.deletedCount,
    attendance: attendance.deletedCount, settlements: settlements.deletedCount,
    collectionRequests: requests.deletedCount, photos: publicIds.length
  };
}

module.exports = { deleteSaloonData, publicIdFromUrl };
